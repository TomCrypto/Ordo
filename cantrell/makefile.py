from __future__ import print_function, division

from cantrell.scanning import SourceTree
from cantrell.resolve import resolve
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
    return path.join(folder, '.lock')


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
            if hasattr(self, 'default'):
                process_alias(f, 'default', self.default)

            for alias in self.aliases:
                process_alias(f, alias, self.aliases[alias])

            for target in self.targets:
                process_target(f, self.targets[target], target)

            for command in self.commands:
                process_command(f, command, self.commands[command])

            folder_rule(f, 'obj')


def gen_makefile(ctx):
    tree = SourceTree('..')
    make = Makefile()

    base_flags = ['-O3', '-Wall', '-Wextra', '-std=c89', '-pedantic',
                  '-Wno-unused-parameter', '-Wno-long-long',
                  '-Wno-missing-braces']

    if not ctx.compat:
        base_flags += ['-Wno-missing-field-initializers']

    if ctx.lto:
        base_flags += ['-flto']
        if ctx.compiler == 'gcc':
            base_flags += ['-ffat-lto-objects']

    env_defines = ['-DORDO_ARCH=\\\"{0}\\\"'.format(ctx.arch),
                   '-DORDO_PLATFORM=\\\"{0}\\\"'.format(ctx.platform),
                   '-DORDO_FEATURE_LIST=\\\"{0}\\\"'.format(' '.join(ctx.features)),
                   '-DORDO_FEATURE_ARRAY=' + ('0' if ctx.features == [] else '\\\"{0}\\\",0'.format('\\\",'.join(ctx.features))),
                   '-DORDO_LITTLE_ENDIAN' if (ctx.platform == 'generic') and (ctx.endian == 'little') else '',
                   '-DORDO_BIG_ENDIAN' if (ctx.platform == 'generic') and (ctx.endian == 'big') else '']

    prim_defines = ['-DWITH_AES=1', '-DWITH_THREEFISH256=1', '-DWITH_NULLCIPHER=1',
                    '-DWITH_RC4=1', '-DWITH_MD5=1', '-DWITH_SHA1=1',
                    '-DWITH_SHA256=1', '-DWITH_SKEIN256=1', '-DWITH_ECB=1',
                    '-DWITH_CBC=1', '-DWITH_CTR=1', '-DWITH_CFB=1',
                    '-DWITH_OFB=1']

    lib_sources = tree.select(ctx.platform, ctx.arch, ctx.features)

    make['libordo_s.a'] = {
        'CFLAGS': base_flags + (['-fvisibility=hidden'] if not ctx.compat else []),
        'DEFINES': ['-DBUILDING_ORDO', '-DORDO_STATIC_LIB'] + env_defines + prim_defines,
        'HEADERS': tree.headers['lib'],
        'INCLUDE': ['-I../include'],
        'DEPS': [],
        'SOURCES': lib_sources,
        '*.c': '{0} $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@'.format(ctx.compiler),
        '*.asm': '{0} -f {1} $< -o $@'.format(ctx.assembler, ctx.obj_format) if ctx.assembler is not None else '',
        '*link': 'ar rcs $@ $^'
    }

    if ctx.shared:
        make['libordo.so'] = {
            'CFLAGS': base_flags + ['-fPIC'] + (['-fvisibility=hidden'] if not ctx.compat else []),
            'DEFINES': ['-DBUILDING_ORDO', '-DORDO_EXPORTS'] + env_defines + prim_defines,
            'HEADERS': tree.headers['lib'],
            'INCLUDE': ['-I../include'],
            'DEPS': [],
            'SOURCES': lib_sources,
            '*.c': '{0} $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@'.format(ctx.compiler),
            '*.asm': '{0} -f {1} $< -o $@'.format(ctx.assembler, ctx.obj_format) if ctx.assembler is not None else '',
            '*link': 'gcc -shared $^ -o $@'
        }

    make['test'] = {
        'CFLAGS': base_flags,
        'DEFINES': ['-DORDO_STATIC_LIB'],
        'HEADERS': list(tree.headers['lib']) + list(tree.headers['test']),
        'INCLUDE': ['-I../include', '-I../test/include'],
        'DEPS': ['libordo_s.a'],
        'SOURCES': tree.src['test'],
        '*.c': 'gcc $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@',
        '*link': 'gcc $^ -o $@ libordo_s.a'
    }

    make['hashsum'] = {
        'CFLAGS': base_flags,
        'DEFINES': ['-DORDO_STATIC_LIB'],
        'HEADERS': tree.headers['lib'],
        'INCLUDE': ['-I../include'],
        'DEPS': ['libordo_s.a'],
        'SOURCES': tree.src['hashsum'],
        '*.c': 'gcc $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@',
        '*link': 'gcc $^ -o $@ libordo_s.a'
    }

    make['version'] = {
        'CFLAGS': base_flags,
        'DEFINES': ['-DORDO_STATIC_LIB'],
        'HEADERS': tree.headers['lib'],
        'INCLUDE': ['-I../include'],
        'DEPS': ['libordo_s.a'],
        'SOURCES': tree.src['version'],
        '*.c': 'gcc $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@',
        '*link': 'gcc $^ -o $@ libordo_s.a'
    }

    make['info'] = {
        'CFLAGS': base_flags,
        'DEFINES': ['-DORDO_STATIC_LIB'],
        'HEADERS': tree.headers['lib'],
        'INCLUDE': ['-I../include'],
        'DEPS': ['libordo_s.a'],
        'SOURCES': tree.src['info'],
        '*.c': 'gcc $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@',
        '*link': 'gcc $^ -o $@ libordo_s.a'
    }

    make['benchmark'] = {
        'CFLAGS': base_flags,
        'DEFINES': ['-DORDO_STATIC_LIB'],
        'HEADERS': list(tree.headers['lib']) + tree.headers['util'],
        'INCLUDE': ['-I../include -I../samples/util/include'],
        'DEPS': ['libordo_s.a', 'libutil.a'],
        'SOURCES': tree.src['benchmark'],
        '*.c': 'gcc $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@',
        '*link': 'gcc $^ -o $@ libordo_s.a libutil.a -lrt'
    }

    make['libutil.a'] = {
        'CFLAGS': base_flags,
        'DEFINES': [],
        'HEADERS': tree.headers['util'],
        'INCLUDE': ['-I../samples/util/include'],
        'DEPS': [],
        'SOURCES': tree.src['util'],
        '*.c': 'gcc $(CFLAGS) $(DEFINES) $(INCLUDE) -c $< -o $@',
        '*link': 'ar rcs $@ $^'
    }

    make.default = ['all']

    make.add_alias('all', ['static', 'shared', 'test', 'samples'])

    make.add_alias('static', ['libordo_s.a'])

    if ctx.shared:
        make.add_alias('shared', ['libordo.so'])
    else:
        make.add_command('shared', ['@echo "Shared library will not be built"',
                                    '@echo "Please configure with --shared"',
                                    ])

    make.add_alias('samples', ['hashsum', 'benchmark', 'version', 'info'])

    make.add_command('doc', ['cd ../doc && doxygen'])
    make.add_command('install', [
        'mkdir -p {0}/include'.format(ctx.prefix),
        'mkdir -p {0}/lib'.format(ctx.prefix),
        'cp -r ../include/ordo.h {0}/include'.format(ctx.prefix),
        'cp -r ../include/ordo {0}/include'.format(ctx.prefix),
        'cp -r libordo_s.a {0}/lib'.format(ctx.prefix),
        'cp -r libordo.so {0}/lib'.format(ctx.prefix) if ctx.shared else ''
    ])

    make.add_command('clean', [
        'rm libordo_s.a',
        'rm libordo.so' if ctx.shared else '',
        'rm hashsum version info benchmark test',
        'rm libutil.a',
        'rm -rf obj'
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
