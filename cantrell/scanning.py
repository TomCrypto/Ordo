from __future__ import print_function, division

from cantrell.utilities import *
from cantrell.detection import *

from os import path
import os

def prefix_search(dirpath):
    return [path.join(root, filename)
            for root, dirnames, filenames in os.walk(dirpath)
            for filename in filenames]

class SourceTree:
    def __init__(self, prefix):
        """Collect all source and header files into a searchable tree."""
        self.src = {}
        self.headers = {}
        self.prefix = prefix
        self.srcdir = path.join(prefix, 'src')
        self.headerdir = path.join(prefix, 'include')
        self.testsrcdir = path.join(prefix, 'test/src')
        self.testheaderdir = path.join(prefix, 'test/include')
        self.utilsrcdir = path.join(prefix, 'samples/util/src')
        self.utilheaderdir = path.join(prefix, 'samples/util/include')

        self.samplessrcdir = path.join(prefix, 'samples/src')

        # Collect all the library files, including definition header
        # (note the files are all given as full paths from the root)

        self.headers['lib'] = set(prefix_search(self.headerdir))
        self.headers['lib'].add('../include/ordo/definitions.h')
        
        self.src['lib'] = self.search_src_lib(self.srcdir, self.prefix)
        
        self.src['test'] = prefix_search(self.testsrcdir)
        self.src['util'] = prefix_search(self.utilsrcdir)
        self.headers['test'] = prefix_search(self.testheaderdir)
        self.headers['util'] = prefix_search(self.utilheaderdir)
        
        self.src['hashsum'] = [path.join(self.samplessrcdir, 'hashsum.c')]
        self.src['version'] = [path.join(self.samplessrcdir, 'version.c')]
        self.src['info'] = [path.join(self.samplessrcdir, 'info.c')]
        self.src['benchmark'] = [path.join(self.samplessrcdir, 'benchmark.c')]
        
        self.headers['hashsum'] = []
        self.headers['version'] = []
        self.headers['info'] = []
        self.headers['benchmark'] = []

    def search_src_lib(self, pR, prefix):
        out = {}
        
        for plat in platform_list:
            for arch in arch_list:
                for feat in feature_list:
                    pP = path.join(pR, plat) if plat != 'generic' else pR
                    pA = path.join(pP, arch) if arch != 'generic' else pP
                    pF = path.join(pA, feat) if feat != 'generic' else pA
                    
                    if not path.isdir(pF):
                        out[(plat, arch, feat)] = []
                        continue

                    out[(plat, arch, feat)] = [path.join(pF, f)
                    for f in os.listdir(pF) if path.isfile(path.join(pF, f))]

        return out

    def same_module(self, file1, file2):
        """Return if two files are (the same part of) the same module."""
        return path.basename(file1) == path.basename(file2)

    def process(self, source_files, category):
        for f in self.src['lib'][category]:
            if not any(self.same_module(f, f2) for f2 in source_files):
                source_files.append(f)
        return source_files

    def select(self, plat, arch, features):
        """Selects the source files to build from platform/arch/features."""
        source_files = []

        for f in set(features).union({'generic'}):
            source_files = self.process(source_files, (plat, arch, f))
        for a in {arch}.union({'generic'}):
            source_files = self.process(source_files, (plat, a, 'generic'))
        for p in {plat}.union({'generic'}):
            source_files = self.process(source_files, (p, 'generic', 'generic'))

        return source_files
