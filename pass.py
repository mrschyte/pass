#!/usr/bin/python

import base64
import click
import os
import pykeepass
import pyperclip
import subprocess
import sys

from time import sleep
from xdo import Xdo

def clip(text, timeout=30):
    orig = pyperclip.paste()
    pyperclip.copy(text)
    newpid = os.fork()
    if newpid == 0:
        sleep(timeout)
        if text in pyperclip.paste():
            pyperclip.copy(orig)
        sys.exit(0)

def die(message):
    print('ERROR: {}'.format(message), file=sys.stderr)
    sys.exit(1)

def get_entry(kdbx, path=None):
    if path == None:
        entry = prompt(kdbx.entries, show=lambda e: "{} ({})".format(e.path, e.username))
        if type(entry) != pykeepass.entry.Entry:
            die('No valid entry was selected.')
        return entry

    entry = kdbx.find_entries_by_path(path, first=True)

    if type(entry) != pykeepass.entry.Entry:
        die('Path "{}" is not a valid entry.'.format(path))

    return entry

def gpg_decrypt(path):
    null = open(os.devnull, 'w')
    return subprocess.check_output(['/usr/bin/gpg', '-d', path], stderr=null).rstrip(b'\n')

def prompt(items, show=str):
    indexed = ['#{0:04x}\t{1}'.format(idx, show(item)) for idx, item in enumerate(items)]
    with subprocess.Popen('/usr/bin/fzf', stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
        proc.stdin.write(os.linesep.join(indexed).encode('utf-8'))
        proc.stdin.flush()
        out = proc.stdout.read().decode('utf-8').rstrip()
        proc.wait()
        if '\t' not in out:
            return None
        idx, _ = tuple(out.split('\t', 1))
    return items[int(idx[1:], 16)]

@click.group()
@click.option('--path', default='{}/.passwords.kdbx'.format(os.environ['HOME']))
@click.pass_context
def cli(ctx, path):
    ctx.ensure_object(dict)
    mkey = gpg_decrypt('{}.gpg'.format(os.path.splitext(path)[0])).decode('utf-8')
    ctx.obj['path'] = path
    ctx.obj['mkey'] = mkey
    ctx.obj['kdbx'] = pykeepass.PyKeePass(path, mkey)

@cli.command()
@click.option('--user/--no-user', default=False)
@click.option('--path', default=None)
@click.pass_context
def copy(ctx, user, path):
    entry = get_entry(ctx.obj['kdbx'], path)
    if user:
        clip(os.linesep.join([entry.username, entry.password]))
    else:
        clip(entry.password)
    print('The password for {} is copied to the clipboard and is erased in {} seconds.'.format(entry.path, 30))

@cli.command()
@click.pass_context
def list(ctx):
    for entry in ctx.obj['kdbx'].entries:
        print('{} ({})'.format(entry.path, entry.username))

@cli.command()
@click.option('--user/--no-user', default=False)
@click.option('--path', default=None)
@click.pass_context
def show(ctx, user, path):
    entry = get_entry(ctx.obj['kdbx'], path)
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
