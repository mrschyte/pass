#!/usr/bin/python

import click
import subprocess
import os
import base64

from pykeepass import PyKeePass
from xdo import Xdo

def gpg_decrypt(path):
    null = open(os.devnull, 'w')
    return subprocess.check_output(['/usr/bin/gpg', '-d', path], stderr=null).rstrip(b'\n')

@click.group()
@click.option('--path', default='{}/.passwords.kdbx'.format(os.environ['HOME']))
@click.pass_context
def cli(ctx, path):
    ctx.ensure_object(dict)
    mkey = gpg_decrypt('{}.gpg'.format(os.path.splitext(path)[0])).decode('utf-8')
    ctx.obj['path'] = path
    ctx.obj['mkey'] = mkey
    ctx.obj['kdbx'] = PyKeePass('{}/.passwords.kdbx'.format(os.environ['HOME']), mkey)

@cli.command()
@click.pass_context
def entries(ctx):
    for entry in ctx.obj['kdbx'].entries:
        print('{} ({})'.format(entry.path, entry.username))

@cli.command()
@click.argument('title')
@click.pass_context
def search(ctx, title):
    for entry in ctx.obj['kdbx'].find_entries_by_title(title):
        print('{} ({})'.format(entry.path, entry.username))

@cli.command()
@click.option('--user/--no-user', default=False)
@click.argument('path')
@click.pass_context
def show(ctx, path, user):
    entry = ctx.obj['kdbx'].find_entries_by_path(path, first=True)
    if user:
        print(entry.username)
    print(entry.password)

@cli.command()
@click.pass_context
def unlock(ctx):
    xdo = Xdo()
    windows = xdo.search_windows(winname=b' - KeePassXC$')
    if len(windows) != 0:
        xdo.enter_text_window(windows[0], ctx.obj['mkey'].encode('utf-8'))
        xdo.send_keysequence_window(windows[0], b'Return')
    else:
        null = open(os.devnull, 'w')
        proc = subprocess.Popen(['/usr/bin/keepassxc', '--pw-stdin', ctx.obj['path']],
                                stdin=subprocess.PIPE, stdout=null, stderr=null)
        proc.stdin.write(ctx.obj['mkey'].encode('utf-8'))

if __name__ == '__main__':
    cli()
