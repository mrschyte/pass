#!/usr/bin/python

import click
import subprocess
import os
import sys
import base64
import pyperclip

from pykeepass import PyKeePass
from time import sleep
from xdo import Xdo

def prompt(items, show=str):
    indexed = ['#{0:04x}\t{1}'.format(idx, show(item)) for idx, item in enumerate(items)]
    with subprocess.Popen('/usr/bin/fzf', stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
        proc.stdin.write(os.linesep.join(indexed).encode('utf-8'))
        proc.stdin.flush()
        out = proc.stdout.read().decode('utf-8').rstrip()
        proc.wait()
        idx, _ = tuple(out.split('\t'))
    return items[int(idx[1:], 16)]

def get_entry(kdbx, path=None):
    if path == None:
        return prompt(kdbx.entries, show=lambda e: "{} ({})".format(e.path, e.username))

    return kdbx.find_entries_by_path(path, first=True)

def clip(text, timeout=30):
    orig = pyperclip.paste()
    pyperclip.copy(text)
    newpid = os.fork()
    if newpid == 0:
        sleep(timeout)
        pyperclip.copy(orig)
        sys.exit(0)

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
    ctx.obj['kdbx'] = PyKeePass(path, mkey)

@cli.command()
@click.pass_context
def list(ctx):
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
@click.option('--path', default=None)
@click.pass_context
def show(ctx, user, path):
    entry = get_entry(ctx.obj['kdbx'], path)
    if user:
        print(entry.username)
    print(entry.password)

@cli.command()
@click.option('--user/--no-user', default=False)
@click.option('--path', default=None)
@click.pass_context
def copy(ctx, user, path):
    entry = get_entry(ctx.obj['kdbx'], path)
    if user:
        clip(os.newline.join([entry.username, entry.password]))
    else:
        clip(entry.password)
    print('The password for {} is copied to the clipboard and is erased in {} seconds.'.format(entry.path, 30))

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
