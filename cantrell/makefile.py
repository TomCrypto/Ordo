from __future__ import print_function, division

from scanning import SourceTree
from resolve import resolve
from detection import *
from utilities import *

from os import path

def gen_makefile(ctx):
    tree = SourceTree('..')
    
    if ctx.compiler in ['gcc', 'clang']:
        cflags = ['-O3', '-Wall', '-Wextra', '-std=c89', '-pedantic',
                  '-fvisibility=hidden', '-Wno-unused-parameter',
                  '-Wno-long-long', '-Wno-missing-braces',
                  '-Wno-missing-field-initializers']
        if ctx.lto:
            if ctx.compiler in ['gcc']:
                cflags += ['-flto -ffat-lto-objects']
            else:
                cflags += ['-flto']
        if not ctx.compat:
            cflags += ['-march=native']
    elif (ctx.compiler == 'icc'):
        pass  # TODO (icc)
    elif (ctx.compiler == 'msvc'):
        pass  # TODO (windows)

    defines = ['-DORDO_STATIC_LIB', '-DBUILDING_ORDO',
               '-DORDO_PLATFORM=\\\"{0}\\\"'.format(ctx.platform),
               '-DORDO_ARCH=\\\"{0}\\\"'.format(ctx.arch),
               '-DORDO_FEATURE_LIST=\\\"{0}\\\"'.format(' '.join(ctx.features))]

    if ctx.features == []:
        defines.append('-DORDO_FEATURE_ARRAY=0')
    else:
        defines.append('-DORDO_FEATURE_ARRAY=\\\"{0}\\\",0'.format('\\\",'.join(ctx.features)))

    if ctx.platform == 'generic':
        defines += ['-DORDO_LITTLE_ENDIAN' if ctx.endian == 'little' else
                    '-DORDO_BIG_ENDIAN']

    to_build = tree.select(ctx.platform, ctx.arch, ctx.features)

    #print("to_build = {0}".format(to_build))

    defines += ['-DWITH_AES=1', '-DWITH_THREEFISH256=1', '-DWITH_NULLCIPHER=1',
                '-DWITH_RC4=1', '-DWITH_MD5=1', '-DWITH_SHA1=1',
                '-DWITH_SHA256=1', '-DWITH_SKEIN256=1', '-DWITH_ECB=1',
                '-DWITH_CBC=1', '-DWITH_CTR=1', '-DWITH_CFB=1',
                '-DWITH_OFB=1']

    with open('Makefile', 'w') as f:
        f.write('HEADERS = {0}\n'.format(' '.join(tree.headers['lib'])))
        f.write('TEST_HEADERS = {0}\n'.format(' '.join(tree.headers['test'])))
        f.write('UTIL_HEADERS = {0}\n'.format(' '.join(tree.headers['util'])))
        f.write('CFLAGS = {0}\n'.format(' '.join(cflags + defines)))
        f.write('TEST_CFLAGS = {0} -DORDO_STATIC_LIB\n'.format(' '.join(cflags)))
        f.write('UTIL_CFLAGS = {0}\n'.format(' '.join(cflags)))
        f.write('SAMPLE_CFLAGS = {0} -DORDO_STATIC_LIB\n'.format(' '.join(cflags)))
        f.write('\n')
        f.write('all: static test\n\n')
        f.write('static: libordo_s.a\n\n')
        f.write('obj:\n\tmkdir obj\n\n')

        objfiles = []
        for srcfile in to_build:
            if '.c' in srcfile:
                objfile = 'obj/' + safe_path(srcfile.replace('.c', '.o'))
                objfiles.append(objfile)
                f.write('{0}: {1} $(HEADERS) | obj\n'.format(objfile, srcfile))
                f.write('\t{0} $(CFLAGS) -I../include -c $< -o $@\n\n'.format(ctx.compiler))
            elif '.asm' in srcfile:
                objfile = 'obj/' + safe_path(srcfile.replace('.asm', '.asm.o'))
                objfiles.append(objfile)
                f.write('{0}: {1} | obj\n'.format(objfile, srcfile))
                f.write('\t{0} -f {1} $< -o $@\n\n'.format(ctx.assembler, ctx.obj_format))

        f.write('libordo_s.a: {0}\n'.format(' '.join(objfiles)))
        f.write('\tar rcs libordo_s.a {0}\n'.format(' '.join(objfiles)))

        test_objfiles = []
        for srcfile in tree.src['test']:
            objfile = 'obj/' + safe_path(srcfile.replace('.c', '.o'))
            test_objfiles.append(objfile)
            f.write('{0}: {1} $(HEADERS) $(TEST_HEADERS) | obj\n'.format(objfile, srcfile))
            f.write('\t{0} $(TEST_CFLAGS) -I../include -I../test/include -c $< -o $@\n\n'.format(ctx.compiler))

        f.write('test: libordo_s.a {0}\n'.format(' '.join(test_objfiles)))
        f.write('\t{0} {1} -o $@ libordo_s.a\n'.format(ctx.compiler, ' '.join(test_objfiles)))

        objfiles = []
        for srcfile in tree.src['util']:
            objfile = 'obj/' + safe_path(srcfile.replace('.c', '.o'))
            objfiles.append(objfile)
            f.write('{0}: {1} $(UTIL_HEADERS) | obj\n'.format(objfile, srcfile))
            f.write('\t{0} $(UTIL_CFLAGS) -I../samples/util/include -c $< -o $@\n\n'.format(ctx.compiler))

        f.write('libutil.a: {0}\n'.format(' '.join(objfiles)))
        f.write('\tar rcs libutil.a {0}\n\n'.format(' '.join(objfiles)))

        f.write('samples: hashsum version info benchmark\n\n')

        for sample in ['hashsum', 'version', 'info', 'benchmark']:
            sample_objfiles = []
            for srcfile in tree.src[sample]:
                objfile = 'obj/' + safe_path(srcfile.replace('.c', '.o'))
                sample_objfiles.append(objfile)
                f.write('{0}: {1} $(HEADERS) $(UTIL_HEADERS) libutil.a {2} | obj\n'.format(objfile, srcfile, ' '.join(tree.headers[sample])))
                f.write('\t{0} $(SAMPLE_CFLAGS) -I../include -I../samples/util/include -c $< -o $@\n\n'.format(ctx.compiler))

            f.write('{0}: libordo_s.a libutil.a {1}\n'.format(sample, ' '.join(sample_objfiles)))
            f.write('\t{0} {1} -o $@ libordo_s.a libutil.a -lrt\n'.format(ctx.compiler, ' '.join(sample_objfiles)))
            # TODO: need realtime library for benchmark on some systems!
            
            f.write('\n')

    # Change directory to root folder (not build), so remove ..
    resolve('../include/ordo/definitions.h', to_build)


def bld_makefile(ctx, targets):
    run_cmd('make', targets, stdout_func=stream)


def ins_makefile(ctx):
    run_cmd('make', ['install'], stdout_func=stream)  # Must handle dependencies!


def tst_makefile(ctx):
    bld_makefile(ctx, ['test'])
    run_cmd('./test', [], stdout_func=stream)  # Must build tests before!
