project('backuprestore',
  'cpp',
  version: '1.0',
  meson_version: '>=0.57.0',
  default_options: [
    'werror=true',
    'warning_level=3',
    'cpp_std=c++20',
    'buildtype=debugoptimized',
  ]
)


conf_data = configuration_data()

conf_data.set_quoted('BACKUP_BUSNAME', 'xyz.openbmc_project.Backup.BackupRestore',
                      description : 'The DBus busname to own.')

conf_header = configure_file(output: 'config.h',
    configuration: conf_data)

phosphor_dbus_interfaces = dependency('phosphor-dbus-interfaces')
sdbusplus = dependency('sdbusplus')
sdeventplus = dependency('sdeventplus')
systemd = dependency('systemd')
phosphor_logging_dep = dependency('phosphor-logging')
openssl_dep = dependency('openssl')



cpp = meson.get_compiler('cpp')

backup_restore_src = [
  'backup_service.hpp',
  'backup_service.cpp'
]

executable(
  'backuprestore',
  'backup_service.cpp',
  dependencies: [
    sdbusplus,
    sdeventplus,
    phosphor_dbus_interfaces,
    phosphor_logging_dep,
    openssl_dep, 
  ],
  link_args: ['-lcrypt', '-lstdc++fs'],
  cpp_args: ['-DBOOST_ALL_NO_LIB', '-DBOOST_SYSTEM_NO_DEPRECATED', '-DBOOST_ERROR_CODE_HEADER_ONLY'],
  install: true,
)
