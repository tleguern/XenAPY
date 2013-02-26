XenAPY
======

XenAPY is Python wrapper arround the Xen REST API.
Citrix publishes an official wrapper, but I don't like it because its GPLed and
not "friendly".

So I rewrote one, ISC licensed and object-oriented.

There is a class per API object, or currently:

   * Session
   * Host
   * CPU
   * PIF - Physical InterFace
   * VM
   * VIF - Virtual InterFace

Attributes from these classes are lazy initialized, in order to save Xen from
flood.

XenAPY is still in an early stage of development, and is currently "read-only",
you can't send request others than getting the value of some fields.

Requirements
------------

You need xmlrpclib, and, obviously, a Xen server.

Exemple
-------

    session = XenAPY.Session("https://xen-1.example.org")
    session.login("login", "password")

    hosts = session.getHosts()
    for host in hosts:
        print host.hostname
        print host.label
        print host.description
        print host.ncpu
        print host.nram

    session.logout()

