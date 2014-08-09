from __future__ import with_statement, division

from cantrell.scanning import SourceTree
from cantrell.resolve import resolve
from cantrell.detection import *

from os import path
from hashlib import sha256


def sanitize(s):
    return s.replace('.', '_').replace('/', '_').upper()


def src2obj(folder, prefix, srcfile):
    join = '_'.join([sanitize(prefix), sanitize(srcfile).lower()])
    return path.join(folder, join) + '.o'  # Guarantees uniqueness


def subst(s, prefix, target, deps=[]):
    s = s.replace('$<', deps[0] if len(deps) != 0 else '')
    s = s.replace('$(', '$(%s_' % sanitize(prefix))
    s = s.replace('$^', ' '.join(deps))
    s = s.replace('$@', target)
    return s


def folder_dep(folder):
    return '.objdir'


def folder_rule(f, folder):
    path = folder_dep(folder)
    f.write('%s:\n' % path)
    f.write('\tmkdir %s\n' % folder)
    f.write('\ttouch %s\n' % path)


def process_alias(f, alias, deps):
    f.write('%s: %s\n\n' % (alias, ' '.join(deps)))


def process_target(f, target, target_name):
    for variable in target:
        if '*' not in variable:
            name = '_'.join([sanitize(target_name).upper(), variable])
            value = ' '.join(target[variable])
            f.write('='.join([name, value]))
            f.write('\n')

    for srcfile in target['SOURCES']:
        deps = [srcfile, '$(HEADERS)', folder_dep('obj')]
        objfile = src2obj('obj', target_name, srcfile)
        ext = path.splitext(srcfile)[1]

        f.write(subst('%s: %s\n\t%s\n\n' % (objfile, ' '.join(deps),
                      target['*' + ext]), target_name, objfile, deps))

    deps = [src2obj('obj', target_name, srcfile)
            for srcfile in target['SOURCES']] + target['DEPS']
    f.write(subst('%s: %s\n\t%s\n\n' % (target_name, ' '.join(deps),
                  target['*link']), target_name, target_name, deps))


def process_command(f, name, commands):
    f.write('%s:\n\t%s\n\n' % (name, '\n\t'.join(commands)))


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
        base_flags += ['-Wno-missing-field-initializers', '-march=native']
        base_flags += [cond(ctx.compiler == 'gcc', '-Wno-maybe-initialized',
                                                   '-Wno-uninitialized')]

    if ctx.lto and ctx.compiler in ['gcc']:
        base_flags += ['-flto', '-ffat-lto-objects']
    elif ctx.lto and ctx.compiler in ['clang']:
        base_flags += ['-flto']

    if target in ['static', 'shared']:
        return base_flags + [
            cond(not ctx.compat, '-fvisibility=hidden'),
            cond(target in ['shared'], '-fPIC')
        ]
    elif target in ['test', 'sample', 'util']:
        return base_flags


def get_intel_flags(ctx, target):
    base_flags = [
        '-O3', '-Wall', '-Wextra', '-std=c89', '-pedantic', '-restrict',
        '-ansi-alias'
    ]

    if ctx.lto:
        base_flags += ['-ipo']

    if target in ['static', 'shared']:
        return base_flags + [
            cond(not ctx.compat, '-fvisibility=hidden'),
            cond(target in ['shared'], '-fPIC')
        ]
    elif target in ['test', 'sample', 'util']:
        return base_flags


def get_flags(ctx, target):
    """Gets appropriate compiler flags depending on the target."""
    if ctx.compiler in ['gcc', 'clang']:
        return get_gcc_clang_flags(ctx, target)
    elif ctx.compiler in ['intel']:
        return get_icc_flags(ctx, target)


def gen_makefile(ctx, build_prefix):
    tree = SourceTree(build_prefix)
    make = Makefile()

    defines = [
        '-DORDO_ARCH=\\\"%s\\\"' % (ctx.arch),
        '-DORDO_PLATFORM=\\\"%s\\\"' % (ctx.platform),
        '-DORDO_FEATURE_LIST=\\\"%s\\\"'% (' '.join(ctx.features))
    ]

    if len(ctx.features) > 0:
        defines += ['-DORDO_FEATURE_ARRAY=\\\"%s\\\",0' % ('\\\",'.join(ctx.features))]
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
        'INCLUDE': ['-I%s' % (tree.inc_dir['lib'])],
        'DEPS': [],
        'SOURCES': lib_sources,
        '*.c': '%s $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@' % (ctx.cc),
        '*.asm': cond(ctx.assembler, '%s -f %s $< -o $@' % (ctx.assembler, ctx.obj_format)),
        '*link': 'ar rcs $@ $^'
    }

    if ctx.shared:
        make['libordo.so'] = {
            'CFLAGS': get_flags(ctx, 'shared'),
            'DEFINES': ['-DBUILDING_ORDO', '-DORDO_EXPORTS'] + defines,
            'HEADERS': tree.headers['lib'],
            'INCLUDE': ['-I%s' % (tree.inc_dir['lib'])],
            'DEPS': [],
            'SOURCES': lib_sources,
            '*.c': '%s $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@' % (ctx.cc),
            '*.asm': cond(ctx.assembler, '%s -f %s $< -o $@' % (ctx.assembler, ctx.obj_format)),
            '*link': '%s -shared $^ -o $@' % ctx.cc
        }

    make['test'] = {
        'CFLAGS': get_flags(ctx, 'test'),
        'DEFINES': ['-DORDO_STATIC_LIB'],
        'HEADERS': tree.headers['lib'] + list(tree.headers['test']),
        'INCLUDE': ['-I%s' % (tree.inc_dir['lib']),
                    '-I%s' % (tree.inc_dir['test'])],
        'DEPS': ['libordo_s.a'],
        'SOURCES': tree.src['test'],
        '*.c': '%s $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@' % ctx.cc,
        '*link': '%s $^ -o $@ libordo_s.a' % ctx.cc
    }

    make['libutil.a'] = {
        'CFLAGS': get_flags(ctx, 'util'),
        'DEFINES': [],
        'HEADERS': tree.headers['util'],
        'INCLUDE': ['-I%s' % (tree.inc_dir['util'])],
        'DEPS': [],
        'SOURCES': tree.src['util'],
        '*.c': '%s $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@' % ctx.cc,
        '*link': 'ar rcs $@ $^'
    }

    for sample in ['hashsum', 'version', 'info', 'benchmark']:
        make[sample] = {
            'CFLAGS': get_flags(ctx, 'sample'),
            'DEFINES': ['-DORDO_STATIC_LIB'],
            'HEADERS': tree.headers['lib'] + tree.headers['util'],
            'INCLUDE': ['-I%s' % (tree.inc_dir['lib']),
                        '-I%s' % (tree.inc_dir['util'])],
            'DEPS': ['libordo_s.a', 'libutil.a'],
            'SOURCES': tree.src[sample],
            'LDFLAGS': [cond(library_exists(ctx.compiler, '-lrt'), '-lrt')],
            '*.c': '%s $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@' % ctx.cc,
            '*link': '%s $^ -o $@ libordo_s.a libutil.a $(LDFLAGS)' % ctx.cc
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
            'mkdir -p %s/include' % (ctx.prefix),
            'mkdir -p %s/lib' % (ctx.prefix),
            'cp -r ../include/ordo.h %s/include' % (ctx.prefix),
            'cp -r ../include/ordo %s/include' % (ctx.prefix),
            'cp -r libordo_s.a %s/lib' % (ctx.prefix),
            cond(ctx.shared, 'cp -r libordo.so %s/lib' % (ctx.prefix))
        ])

    make.add_command('clean', [
        'rm -rf libordo_s.a',
        cond(ctx.shared, 'rm -rf libordo.so', 'rm -rf shared'),
        'rm -rf hashsum version info benchmark test',
        'rm -rf libutil.a',
        'rm -rf obj',
        'rm -rf %s' % (folder_dep('obj'))
    ])

    make.generate('Makefile')  # All done
    resolve(tree.def_header, lib_sources)


def bld_makefile(ctx, targets):
    run_cmd('make', targets, stdout_func=stream)


def ins_makefile(ctx):
    run_cmd('make', ['install'], stdout_func=stream)


def tst_makefile(ctx):
    bld_makefile(ctx, ['test'])
    run_cmd('./test', [], stdout_func=stream)
