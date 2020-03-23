import os.path
import sys
import ntpath
from subprocess import Popen, check_output
import csv

lib_dir = '/lib/x86_64-linux-gnu/'

libraries = [
    # GLIBC
    'libc.so.6',
    'libm.so.6',
    'libpthread-2.27.so',
    'libnsl-2.27.so',
    'ld-2.27.so',
    'libresolv-2.27.so',
    'libnss_files-2.27.so',
    'librt-2.27.so',
    'libnss_nisplus-2.27.so',
    'libnss_nis-2.27.so',
    'libthread_db-1.0.so',
    'libnss_compat-2.27.so',
    'libnss_hesiod-2.27.so',
    'libcrypt-2.27.so',
    'libdl-2.27.so',
    'libcidn-2.27.so',
    'libnss_dns-2.27.so',
    'libmemusage.so',
    'libanl-2.27.so',
    'libutil-2.27.so',
    'libpcprofile.so',
    'libSegFault.so',
    'libBrokenLocale-2.27.so',

    #GTK
    'libgtk-3.so.0',
    'libgdk-3.so.0',
    # 'libgailutil',

    # GLib
    #'libglib-2.0.so.0',

    # GPG
    'libgcrypt.so.20',
    
    # OpenSSL
    #'libcrypto.so.1.0.0',
    #'libssl.so.1.0.0',

    #httpd
    # 'httpd',
    # 'libapr',
    # 'libaprutil',

    # SQLite
    'libsqlite3.so.0',
    # 'sqlite',

    # D-Bus
    'libdbus-1.so.3'
]

otherLibs = {}
# Haskell
otherLibs['pandoc'] = '/home/atsuko/pandoc-2.9.2/bin/pandoc'
otherLibs['darcs'] = '/usr/bin/darcs'
otherLibs['xmonad'] = '/usr/bin/xmonad'
# OCaml
otherLibs['opam'] = '/usr/local/bin/opam'
otherLibs['bap'] = '/home/atsuko/.opam/4.07.0/bin/bap'
otherLibs['dune'] = '/home/atsuko/.opam/4.07.0/bin/dune'

failed = []
data_columns = ['lib', 'num dispatchers']
data_rows = []

def getNumGadgets(path, lib):
    args = [
        'python',
        'ROPgadget.py',
        '--norop',
        '--nosys',
        '--disp',
        '--binary',
        path
    ]
    print(" ".join(args))
    out = check_output(args)
    
    outfile = lib + '-disp.out'
    f = open(outfile, 'w')
    f.write(out)
    f.close()
    print('Wrote to %s' % outfile)

    out = [x for x in out.split('\n') if x != '']
    last = out[-1]
    numGadgets = int(last.split(' ')[-1])
    
    row = [lib, numGadgets]            
    data_rows.append(row)
    
    return numGadgets

for i, lib in enumerate(libraries):
    path = lib_dir + lib
    # exceptions to library path name
    if 'gtk'in lib or 'gdk' in path or 'sql' in path:
        path = '/usr' + path

    try:
        print('%i/%i: %s' % (i+1, len(libraries), lib))
        n = getNumGadgets(path, lib)
        print('%s: %i gadgets' % (lib, n))
        print('---')
    except Exception as e:
        print('%s failed' % path)
        failed.append(lib + ': ' + path)
        print(e)

for app in otherLibs.keys():
    path = otherLibs[app]
    try:
        n = getNumGadgets(path, app)
        print('%s: %i gadgets' % (lib, n))
    except Exception as e:
        print('%s failed' % path)
        failed.append(app + ': ' + path)
        print(e)

# compile all data to one csv file
csv_file = "all-disp.csv"
with open(csv_file, 'w') as csvfile: # all of the data will be written into this master file
    filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)   
    filewriter.writerow(data_columns);
    for r in data_rows:
        filewriter.writerow(r)
csvfile.close()

if len(failed) > 0:
    print('Failed to search %i libraries' % len(failed))
    for i, f in enumerate(failed):
        print("%i/%i: %s" % (i+1, len(failed), f))
else:
    print('All %i libraries were searched successfully. Data written to %s' % (len(libraries), csv_file))
