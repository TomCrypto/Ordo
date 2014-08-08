"""The module is responsible for generating makefiles for GCC, Clang, and the
   Intel compilers. The MSVC compiler does not support makefiles.            """

from __future__ import print_function, division

from cantrell.scanning import SourceTree
from cantrell.resolve import resolve
from cantrell.detection import *
from cantrell.utilities import *

from os import path


def sanitize(s):
    return s.replace('.', '_').replace('/', '_').upper()


def src2obj(folder, prefix, srcfile):
    new = path.join(folder, safe_path(path.join(prefix, srcfile)))
    return new.replace('.c', '.o')


def subst(s, prefix, target, deps=[]):
    s = s.replace('$<', deps[0] if len(deps) != 0 else '')
    s = s.replace('$(', '$({0}_'.format(sanitize(prefix)))
    s = s.replace('$^', ' '.join(deps))
    s = s.replace('$@', target)
    return s


def folder_dep(folder):
    return '.objdir'


def folder_rule(f, folder):
    path = folder_dep(folder)
    f.write('{0}:\n'.format(path))
    f.write('\tmkdir {0}\n'.format(folder))
    f.write('\ttouch {0}\n'.format(path))


def process_alias(f, alias, deps):
    f.write('{0}: {1}\n\n'.format(alias, ' '.join(deps)))


def process_target(f, target, target_name):
    for variable in target:
        if '*' not in variable:
            name = '_'.join([sanitize(target_name), variable])
            value = ' '.join(target[variable])
            f.write('='.join([name, value]))
            f.write('\n')

    for srcfile in target['SOURCES']:
        deps = [srcfile, '$(HEADERS)', folder_dep('obj')]
        objfile = src2obj('obj', target_name, srcfile)
        ext = path.splitext(srcfile)[1]

        f.write(subst('{0}: {1}\n\t{2}\n\n'.format(objfile, ' '.join(deps),
                      target['*' + ext]), target_name, objfile, deps))

    deps = [src2obj('obj', target_name, srcfile)
            for srcfile in target['SOURCES']] + target['DEPS']
    f.write(subst('{0}: {1}\n\t{2}\n\n'.format(target_name, ' '.join(deps),
                  target['*link']), target_name, target_name, deps))


def process_command(f, name, commands):
    f.write('{0}:\n\t{1}\n\n'.format(name, '\n\t'.join(commands)))


class Makefile:
    """A makefile generator which helps to write compilation rules."""
    def __init__(self):
        self.commands = {}
        self.targets = {}
        self.aliases = {}

    def __getitem__(self, name):
        return self.targets[name]

    def __setitem__(self, name, value):
        self.targets[name] = value

    def add_alias(self, alias, deps):
        self.aliases[alias] = deps

    def add_command(self, name, commands):
        self.commands[name] = commands

    def generate(self, path):
        with open(path, 'w') as f:
            if hasattr(self, 'all'):
                process_alias(f, 'all', self.all)

            for alias in self.aliases:
                process_alias(f, alias, self.aliases[alias])

            for target in self.targets:
                process_target(f, self.targets[target], target)

            for command in self.commands:
                process_command(f, command, self.commands[command])

            folder_rule(f, 'obj')


def get_gcc_clang_flags(ctx, target):
    base_flags = [
        '-O3', '-Wall', '-Wextra', '-std=c89', '-pedantic', '-Wno-long-long',
        '-Wno-unused-parameter', '-Wno-missing-braces'
    ]

    if not ctx.compat:
        base_flags += ['-Wno-missing-field-initializers', '-march=native',
                       '-Wno-maybe-initialized']

    if ctx.lto and ctx.compiler in ['gcc']:
        base_flags += ['-flto', '-ffat-lto-objects']
    elif ctx.lto and ctx.compiler in ['clang']:
        base_flags += ['-flto']

    if target in ['static', 'shared']:
        out = base_flags + (['-fvisibility=hidden'] if ctx.compat else [])
        if target in ['shared']:
            return out + ['-fPIC']
        else:
            return out
    elif target in ['shared']:
        return base_flags + ['-fPIC', cond(ctx.compat, '-fvisibility=hidden')]
    elif target in ['test', 'sample', 'util']:
        return base_flags


def get_icc_flags(ctx, target):
    base_flags = [
        '-O3', '-Wall', '-Wextra', '-std=c89', '-pedantic', '-restrict',
        '-ansi-alias'
    ]

    if ctx.lto:
        base_flags += ['-ipo']

    if target in ['static', 'shared']:
        out = base_flags + (['-fvisibility=hidden'] if ctx.compat else [])
        if target in ['shared']:
            return out + ['-fPIC']
        else:
            return out
    elif target in ['shared']:
        return base_flags + ['-fPIC', cond(ctx.compat, '-fvisibility=hidden')]
    elif target in ['test', 'sample', 'util']:
        return base_flags


def get_flags(ctx, target):
    """Gets appropriate compiler flags depending on the target."""
    if ctx.compiler in ['gcc', 'clang']:
        return get_gcc_clang_flags(ctx, target)
    elif ctx.compiler in ['icc']:
        return get_icc_flags(ctx, target)


def gen_makefile(ctx):
    tree = SourceTree('..')
    make = Makefile()

    defines = [
        '-DORDO_ARCH=\\\"{0}\\\"'.format(ctx.arch),
        '-DORDO_PLATFORM=\\\"{0}\\\"'.format(ctx.platform),
        '-DORDO_FEATURE_LIST=\\\"{0}\\\"'.format(' '.join(ctx.features))
    ]

    if len(ctx.features) > 0:
        defines += ['-DORDO_FEATURE_ARRAY=\\\"{0}\\\",0'
                    .format('\\\",'.join(ctx.features))]
    else:
        defines += ['-DORDO_FEATURE_ARRAY=0']

    if ctx.platform in ['generic']:
        if ctx.endian in ['little']:
            defines += ['-DORDO_LITTLE_ENDIAN']
        else:
            defines += ['-DORDO_BIG_ENDIAN']

    defines += [
        '-DWITH_AES=1', '-DWITH_THREEFISH256=1', '-DWITH_NULLCIPHER=1',
        '-DWITH_RC4=1', '-DWITH_MD5=1', '-DWITH_SHA1=1',
        '-DWITH_SHA256=1', '-DWITH_SKEIN256=1', '-DWITH_ECB=1',
        '-DWITH_CBC=1', '-DWITH_CTR=1', '-DWITH_CFB=1',
        '-DWITH_OFB=1'
    ]

    lib_sources = tree.select(ctx.platform, ctx.arch, ctx.features)

    make['libordo_s.a'] = {
        'CFLAGS': get_flags(ctx, 'static'),
        'DEFINES': ['-DBUILDING_ORDO', '-DORDO_STATIC_LIB'] + defines,
        'HEADERS': tree.headers['lib'],
        'INCLUDE': ['-I../include'],
        'DEPS': [],
        'SOURCES': lib_sources,
        '*.c': '{0} $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@'.format(ctx.compiler),
        '*.asm': cond(ctx.assembler, '{0} -f {1} $< -o $@'.format(ctx.assembler, ctx.obj_format)),
        '*link': 'ar rcs $@ $^'
    }

    if ctx.shared:
        make['libordo.so'] = {
            'CFLAGS': get_flags(ctx, 'shared'),
            'DEFINES': ['-DBUILDING_ORDO', '-DORDO_EXPORTS'] + defines,
            'HEADERS': tree.headers['lib'],
            'INCLUDE': ['-I../include'],
            'DEPS': [],
            'SOURCES': lib_sources,
            '*.c': '{0} $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@'.format(ctx.compiler),
            '*.asm': cond(ctx.assembler, '{0} -f {1} $< -o $@'.format(ctx.assembler, ctx.obj_format)),
            '*link': 'gcc -shared $^ -o $@'
        }

    make['test'] = {
        'CFLAGS': get_flags(ctx, 'test'),
        'DEFINES': ['-DORDO_STATIC_LIB'],
        'HEADERS': list(tree.headers['lib']) + list(tree.headers['test']),
        'INCLUDE': ['-I../include', '-I../test/include'],
        'DEPS': ['libordo_s.a'],
        'SOURCES': tree.src['test'],
        '*.c': 'gcc $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@',
        '*link': 'gcc $^ -o $@ libordo_s.a'
    }

    make['libutil.a'] = {
        'CFLAGS': get_flags(ctx, 'util'),
        'DEFINES': [],
        'HEADERS': tree.headers['util'],
        'INCLUDE': ['-I../samples/util/include'],
        'DEPS': [],
        'SOURCES': tree.src['util'],
        '*.c': 'gcc $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@',
        '*link': 'ar rcs $@ $^'
    }

    for sample in ['hashsum', 'version', 'info', 'benchmark']:
        make[sample] = {
            'CFLAGS': get_flags(ctx, 'sample'),
            'DEFINES': ['-DORDO_STATIC_LIB'],
            'HEADERS': list(tree.headers['lib']) + tree.headers['util'],
            'INCLUDE': ['-I../include -I../samples/util/include'],
            'DEPS': ['libordo_s.a', 'libutil.a'],
            'SOURCES': tree.src[sample],
            'LDFLAGS': [cond(library_exists(ctx.compiler, '-lrt'), '-lrt')],
            '*.c': 'gcc $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@',
            '*link': 'gcc $^ -o $@ libordo_s.a libutil.a $(LDFLAGS)'
        }

    make.all = ['static', 'shared', 'test', 'samples']

    make.add_alias('static', ['libordo_s.a'])

    if ctx.shared:
        make.add_alias('shared', ['libordo.so'])
    else:
        make.add_command('shared', [
            'echo "Shared library will not be built." > shared',
            'echo "Please configure (with --shared)." >> shared'
        ])

    make.add_alias('samples', ['hashsum', 'benchmark', 'version', 'info'])

    make.add_command('doc', ['cd ../doc && doxygen'])

    if ctx.platform != 'generic':
        make.add_command('install', [
            'mkdir -p {0}/include'.format(ctx.prefix),
            'mkdir -p {0}/lib'.format(ctx.prefix),
            'cp -r ../include/ordo.h {0}/include'.format(ctx.prefix),
            'cp -r ../include/ordo {0}/include'.format(ctx.prefix),
            'cp -r libordo_s.a {0}/lib'.format(ctx.prefix),
            cond(ctx.shared, 'cp -r libordo.so {0}/lib'.format(ctx.prefix))
        ])

    make.add_command('clean', [
        'rm -rf libordo_s.a',
        cond(ctx.shared, 'rm -rf libordo.so', 'rm -rf shared'),
        'rm -rf hashsum version info benchmark test',
        'rm -rf libutil.a',
        'rm -rf obj',
        'rm -rf {0}'.format(folder_dep('obj'))
    ])

    make.generate('Makefile')  # Output the file
    resolve(tree.definition_header, lib_sources)


def bld_makefile(ctx, targets):
    run_cmd('make', targets, stdout_func=stream)


def ins_makefile(ctx):
    run_cmd('make', ['install'], stdout_func=stream)


def tst_makefile(ctx):
    bld_makefile(ctx, ['test'])
    run_cmd('./test', [], stdout_func=stream)
