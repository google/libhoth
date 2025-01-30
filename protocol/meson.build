protocol_srcs = [
  'host_cmd.c',
]

incdir = include_directories('..')

libhoth_protocol = library('hoth_protocols', protocol_srcs, include_directories: incdir, link_with: [libhoth_transport])
