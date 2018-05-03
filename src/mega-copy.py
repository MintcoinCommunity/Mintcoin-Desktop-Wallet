import os
import os.path
import sys

import mega

# constants for various types of things on MEGA.nz
MEGA_FILE = 0
MEGA_DIR = 1
MEGA_CLOUD_DRIVE = 2
MEGA_INBOX = 3
MEGA_TRASH_BIN = 4

# check our login/password
mega_email = os.getenv('MEGA_EMAIL')
if mega_email is None:
    print("Please set the MEGA_EMAIL environment variable")
    sys.exit(1)
mega_password = os.getenv('MEGA_PASSWORD')
if mega_password is None:
    print("Please set the MEGA_PASSWORD environment variable")
    sys.exit(1)

# check our arguments
if len(sys.argv) != 3:
    print("Syntax: %s source_file dest_file" % sys.argv[0])
    sys.exit(1)
src_name = sys.argv[1]
dst_name = sys.argv[2]

# log on to MEGA.nz
mega_instance = mega.Mega()
m = mega_instance.login(mega_email, mega_password)

# get all of our existing nodes on MEGA.nz
mega_cloud_drive_handle = None
nodes_by_handle = {}
for node in m.get_files().values():
    handle = node['h']
    nodes_by_handle[handle] = node
    if node['t'] == MEGA_CLOUD_DRIVE:
        mega_cloud_drive_handle = node['h']

# make a path-like name for each node
# NOTE: this won't work if you have a name with a '/' in it
nodes_by_name = {}
for node in nodes_by_handle.values():
    # Some nodes have a string for the 'a' value (possibly these are
    # deleted nodes). We only understand nodes with a dictionary
    # there.
    if type(node['a']) is not dict:
        continue
    rev_path = [node['a']['n'],]
    path_node = node
    while path_node['p']:
        path_node = nodes_by_handle[path_node['p']]
        rev_path.append(path_node['a']['n'])
    rev_path.reverse()
    name = '/'.join(rev_path)
    nodes_by_name[name] = node

# create the named directory and all parent directories
def create_dir(path):
    global nodes_by_name
    if path in nodes_by_name:
        return nodes_by_name[path]
    parent, base = os.path.split(path)
    if not parent:
        data = m.create_folder(base)
    else:
        parent_node = create_dir(parent)
        parent_node = nodes_by_name[parent]
        data = m.create_folder(base, parent_node['h'])
    new_node = data['f'][0]
    new_node['a'] = {'n': base}
    nodes_by_name[path] = new_node
    return new_node

# stick our files in the "Cloud Drive" at MEGA.nz
full_dst_name = os.path.normpath(os.path.join('Cloud Drive', dst_name))

# either create or return the node for the directory of our destination
dst_dir_node = create_dir(os.path.dirname(full_dst_name))

# remove the current file at the destination, if it exists
if full_dst_name in nodes_by_name:
    m.destroy(nodes_by_name[full_dst_name]['h'])

# finally, upload the file to the destination
dst_dir_handle = dst_dir_node['h']
dst_base_filename = os.path.basename(dst_name)
m.upload(src_name, dest=dst_dir_handle, dest_filename=dst_base_filename)
