from __future__ import with_statement
from cantrell.detection import *
from cantrell.scanning import *
from os import path


def gen_solution(ctx, build_prefix):
    raise NotImplementedError()


def bld_solution(ctx, targets):
    raise NotImplementedError()


def ins_solution(ctx):
    raise NotImplementedError()


def tst_solution(ctx):
    raise NotImplementedError()
