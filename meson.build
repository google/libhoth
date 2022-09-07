project(
  'libhoth',
  'c',
  license: 'Apache-2.0',
  version: '0.0.0',
  default_options: [
    'examples=' + (meson.is_subproject() ? 'false' : 'true'),
  ])

hoth_usb_deps = [
  dependency('libusb-1.0'),
]

hoth_usb_pre = declare_dependency(
  include_directories: include_directories('.'),
  dependencies: hoth_usb_deps)

hoth_usb_lib = library(
  'hoth_usb',
  'libhoth_usb.c',
  'libhoth_usb_fifo.c',
  'libhoth_usb_mailbox.c',
  dependencies: hoth_usb_pre,
  install: true,
  version: meson.project_version())

hoth_usb_dep = declare_dependency(
  link_with: hoth_usb_lib,
  dependencies: hoth_usb_pre)

install_headers('libhoth_usb.h')

hoth_usb_reqs = []
foreach dep : hoth_usb_deps
  if dep.type_name() == 'pkgconfig'
    hoth_usb_reqs += dep
  endif
endforeach

pkg = import('pkgconfig')
pkg.generate(
  hoth_usb_lib,
  name: 'libhoth_usb',
  description: 'Hoth USB interface library',
  requires: hoth_usb_reqs)

if get_option('examples')
  subdir('examples')
endif
