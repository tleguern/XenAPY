#!/usr/bin/python
#
# Copyright (c) 2013 Tristan Le Guern <leguern AT medu DOT se>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import time
import sys
import xmlrpclib

# TODO:
# [X] Force utf-8 encoding for strings
# [X] Force int conversion for numbers
# [ ] class VBD
# [ ] class VDI
# [ ] class SR
# [ ] class PBD
# [X] class Session
# [X] class Host
#     [X] method ncpu - get the number of CPU attached to this host
#     [X] method cpus - get a list of CPU object attached to this host
#     [X] class CPU
#     [X] class PIF
#     [X] class VM
#         [X] class VIF
#     [ ] class PGPU
#     [ ] class PCI
# [ ] class Network

# Helpers functions and classes

def checkAPIResult(res):
    if type(res) != dict or 'Status' not in res:
        raise xmlrpclib.Fault(500, 'Bad response from server' + res)

    if res['Status'] != 'Success':
        if 'ErrorDescription' in res:
            raise xmlrpclib.Fault(500, res['ErrorDescription'])
        else:
            raise xmlrpclib.Fault(500, 'Bad response from server')

    return res['Value']

class Base(object, xmlrpclib.ServerProxy):
    def __init__(self, uri):
        xmlrpclib.ServerProxy.__init__(self, uri, None, None, 0, 1)
        session = None

class ReadOnlyCachedAttribute(object):    
    '''This decorator allows you to create a property which will be lazy
    initialized and cached for later access.
    Inspired from Denis Otkidach work, under PSF license.
    '''
    def __init__(self, method, name=None):
        self.method = method
        self.name = name or method.__name__
        self.__doc__ = method.__doc__
    def __get__(self, inst, cls): 
        if inst is None:
            return self
        elif self.name in inst.__dict__:
            return inst.__dict__[self.name]
        else:
            result = self.method(inst)
            inst.__dict__[self.name]=result
            return result    
    def __set__(self, inst, value):
        raise AttributeError("This property is read-only")
    def __delete__(self,inst):
        del inst.__dict__[self.name]

class ReadOnlyAttribute(object):    
    ''' This decorator allows you to create a property which will be lazy
    initilized, but recomputed at every access.
    Inspired from Denis Otkidach work, under PSF license.
    '''
    def __init__(self, method, name=None):
        self.method = method
        self.name = name or method.__name__
        self.__doc__ = method.__doc__
    def __get__(self, inst, cls): 
        if inst is None:
            return self
        else:
            result = self.method(inst)
            return result    
    def __set__(self, inst, value):
        raise AttributeError("This property is read-only")
    def __delete__(self,inst):
        del inst.__dict__[self.name]


# API Classes

class CPU(object):
    def __init__(self, uuid):
        self.api = Session.api
        self.uuid = uuid

    @ReadOnlyCachedAttribute
    def family(self):
        ret = self.api.host_cpu.get_family(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def features(self):
        ret = self.api.host_cpu.get_features(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def flags(self):
        ret = self.api.host_cpu.get_flags(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def model(self):
        ret = self.api.host_cpu.get_model(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def modelname(self):
        ret = self.api.host_cpu.get_modelname(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def number(self):
        ret = self.api.host_cpu.get_number(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def stepping(self):
        ret = self.api.host_cpu.get_stepping(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def speed(self):
        ret = self.api.host_cpu.get_speed(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def utilisation(self):
        ret = self.api.host_cpu.get_utilisation(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def vendor(self):
        ret = self.api.host_cpu.get_vendor(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def other_config(self):
        ret = self.api.host_cpu.get_other_config(self.api.session, self.uuid)
        return checkAPIResult(ret)

    def dump(self):
        print "=== {0} ===".format(self.number)
        print "{0}".format(self.family)
        print "{0}".format(self.features)
        print "{0}".format(self.flags)
        print "{0}".format(self.model)
        print "{0}".format(self.modelname)
        print "{0}".format(self.stepping)
        print "{0}".format(self.speed)
        print "{0}".format(self.utilisation)
        print "{0}".format(self.vendor)
        print "{0}".format(self.other_config)

class PIF(object):
    def __init__(self, uuid):
        self.api = Session.api
        self.uuid = uuid

    @ReadOnlyAttribute
    def device(self):
        ret = self.api.PIF.get_device(self.api.session, self.uuid)
        return int(checkAPIResult(ret))

    @ReadOnlyAttribute
    def dns(self):
        ret = self.api.PIF.get_DNS(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyAttribute
    def ipv4(self):
        ret = self.api.PIF.get_IP(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyAttribute
    def ipv4gateway(self):
        ret = self.api.PIF.get_gateway(self.api.session, self.uuid)
        return checkAPIResult(ret)

    #@ReadOnlyCachedAttribute
    #def ipv6(self):
    #    ret = self.api.PIF.get_ipv6(self.api.session, self.uuid)
    #    return checkAPIResult(ret)

    #@ReadOnlyCachedAttribute
    #def ipv6gateway(self):
    #    ret = self.api.PIF.get_ipv6_gateway(self.api.session, self.uuid)
    #    return checkAPIResult(ret)

    @ReadOnlyAttribute
    def mac(self):
        ret = self.api.PIF.get_MAC(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyAttribute
    def mtu(self):
        ret = self.api.PIF.get_MTU(self.api.session, self.uuid)
        return int(checkAPIResult(ret))

    @ReadOnlyAttribute
    def netmask(self):
        ret = self.api.PIF.get_netmask(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def physical(self):
        ret = self.api.PIF.get_physical(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyAttribute
    def vlan(self):
        ret = self.api.PIF.get_VLAN(self.api.session, self.uuid)
        return int(checkAPIResult(ret))

    def dump(self):
        print "=== {0} ===".format(self.device)
        print "{0}".format(self.dns)
        print "{0}".format(self.ipv4)
        print "{0}".format(self.ipv4gateway)
        #print "{0}".format(self.ipv6)
        #print "{0}".format(self.ipv6gateway)
        print "{0}".format(self.mac)
        print "{0}".format(self.mtu)
        print "{0}".format(self.netmask)
        print "{0}".format(self.physical)
        print "{0}".format(self.vlan)

class Host(object):
    def __init__(self, uuid):
        self.api = Session.api
        self.uuid = uuid

    @ReadOnlyAttribute
    def address(self):
        ret = self.api.host.get_address(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyAttribute
    def hostname(self):
        ret = self.api.host.get_hostname(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyAttribute
    def label(self):
        ret = self.api.host.get_name_label(self.api.session, self.uuid)
        return checkAPIResult(ret).encode("utf-8")

    @ReadOnlyAttribute
    def description(self):
        ret = self.api.host.get_name_description(self.api.session, self.uuid)
        return checkAPIResult(ret).encode("utf-8")

    @ReadOnlyCachedAttribute
    def logging(self):
        ret = self.api.host.get_logging(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def cpus(self):
        cpus_list = []
        ret = self.api.host.get_host_CPUs(self.api.session, self.uuid)
        for cpu in checkAPIResult(ret):
            cpus_list.append(CPU(cpu))
        return cpus_list

    @ReadOnlyCachedAttribute
    def ncpu(self):
        return len(self.cpus)

    @ReadOnlyCachedAttribute
    def pifs(self):
        pifs_list = []
        ret = self.api.host.get_PIFs(self.api.session, self.uuid)
        for pif in checkAPIResult(ret):
            pifs_list.append(PIF(pif))
        return pifs_list

    @ReadOnlyCachedAttribute
    def npif(self):
        return len(self.pifs)

    @ReadOnlyAttribute
    def vms(self):
        vms_list = []
        ret = self.api.host.get_resident_VMs(self.api.session, self.uuid)
        for vm in checkAPIResult(ret):
            vms_list.append(VM(vm))
        return vms_list

    @ReadOnlyAttribute
    def nvm(self):
        return len(self.vms)

    @ReadOnlyCachedAttribute
    def nram(self):
        ret = self.api.host.get_metrics(self.api.session, self.uuid)
        muuid = checkAPIResult(ret)
        ret = self.api.host_metrics.get_memory_total(self.api.session, muuid)
        return int(checkAPIResult(ret))

    @ReadOnlyAttribute
    def nramFree(self):
        ret = self.api.host.get_metrics(self.api.session, self.uuid)
        muuid = checkAPIResult(ret)
        ret = self.api.host_metrics.get_memory_free(self.api.session, muuid)
        return int(checkAPIResult(ret))

    def dump(self):
        print "Hostname: {0}".format(self.hostname)
        print "Label: {0}".format(self.label)
        print "Description: {0}".format(self.description)
        print "Address:{0}".format(self.address)
        print "logging: {0}".format(self.logging)
        print "ncpu: {0}".format(self.ncpu)
        print "npif: {0}".format(self.npif)
        print "nvm: {0}".format(self.nvm)

class VIF(object):
    def __init__(self, uuid):
        self.api = Session.api
        self.uuid = uuid

    @ReadOnlyCachedAttribute
    def plugged(self):
        ret = self.api.VIF.get_currently_attached(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyAttribute
    def device(self):
        ret = self.api.VIF.get_device(self.api.session, self.uuid)
        return int(checkAPIResult(ret))

    @ReadOnlyAttribute
    def mac(self):
        ret = self.api.VIF.get_MAC(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyAttribute
    def mtu(self):
        ret = self.api.VIF.get_MTU(self.api.session, self.uuid)
        return int(checkAPIResult(ret))

    @ReadOnlyAttribute
    def runtime_properties(self):
        ret = self.api.VIF.get_runtime_properties(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyAttribute
    def other_config(self):
        ret = self.api.VIF.get_other_config(self.api.session, self.uuid)
        return checkAPIResult(ret)

    def dump(self):
        print "=== {0} ===".format(self.device)
        print "plugged: {0}".format(self.plugged)
        print "MAC: {0}".format(self.mac)
        print "MTU: {0}".format(self.mtu)
        print "runtime_properties: {0}".format(self.runtime_properties)
        print "other_config: {0}".format(self.other_config)

class VM(object):
    def __init__(self, uuid):
        self.api = Session.api
        self.uuid = uuid

    @ReadOnlyCachedAttribute
    def domid(self):
        ret = self.api.VM.get_domid(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def isASnapshot(self):
        ret = self.api.VM.get_is_a_snapshot(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def isATemplate(self):
        ret = self.api.VM.get_is_a_template(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def isControlDomain(self):
        ret = self.api.VM.get_is_control_domain(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyAttribute
    def label(self):
        ret = self.api.VM.get_name_label(self.api.session, self.uuid)
        return checkAPIResult(ret).encode("utf-8")

    @ReadOnlyAttribute
    def description(self):
        ret = self.api.VM.get_name_description(self.api.session, self.uuid)
        return checkAPIResult(ret).encode("utf-8")

    @ReadOnlyAttribute
    def tags(self):
        ret = self.api.VM.get_tags(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyAttribute
    def power(self):
        ret = self.api.VM.get_power_state(self.api.session, self.uuid)
        return checkAPIResult(ret)

    @ReadOnlyCachedAttribute
    def nvcpu(self):
        ret = self.api.VM.get_VCPUs_at_startup(self.api.session, self.uuid)
        return int(checkAPIResult(ret))

    @ReadOnlyCachedAttribute
    def nvram(self):
        ret = self.api.VM.get_memory_target(self.api.session, self.uuid)
        return int(checkAPIResult(ret))

    @ReadOnlyAttribute
    def vifs(self):
        vifs_list = []
        ret = self.api.VM.get_VIFs(self.api.session, self.uuid)
        for vif in checkAPIResult(ret):
            vifs_list.append(VIF(vif))
        return vifs_list

    @ReadOnlyAttribute
    def nvif(self):
        return len(self.vifs)

    def dump(self):
        print "domid: {0}".format(self.domid)
        print "is a snapshot?: {0}".format(self.isASnapshot)
        print "is a template?: {0}".format(self.isATemplate)
        print "is control domain?: {0}".format(self.isControlDomain)
        print "label: {0}".format(self.label)
        print "description: {0}".format(self.description)
        print "tags: {0}".format(self.tags)
        print "power: {0}".format(self.power)
        print "nvcpu: {0}".format(self.nvcpu)
        print "nvram: {0}".format(self.nvram)
        print "nvif: {0}".format(self.nvif)

class Session(object):
    api = None

    def __init__(self, uri):
        Session.api = Base(uri)

    def login(self, user, password):
        result = self.api.session.login_with_password(user, password)        
        self.api.session = checkAPIResult(result)

    def logout(self):
        self.api.logout(self.api.session)
        self.api.session = None

    def getVMByLabel(self, label):
        res = self.api.VM.get_by_name_label(self.api.session, label)
        all = checkAPIResult(res)
        good = None
        for a in all:
            res = self.api.VM.get_name_label(self.api.session, a)
            vm_name = checkAPIResult(res)
            if vm_name == label:
                good = a
                break
        vm = VM(good)
        return vm

    def getVMs(self):
        all = checkAPIResult(self.api.VM.get_all(self.api.session))
        vms = []
        for a in all:
            res = self.api.VM.get_record(self.api.session, a)
            record = checkAPIResult(res)
            if not(record["is_a_template"]) and not(record["is_control_domain"]):
                vms.append(VM(a))
                time.sleep(0.1)
        return vms

    def getHosts(self):
        all = checkAPIResult(self.api.host.get_all(self.api.session))
        hosts = []
        for a in all:
            hosts.append(Host(a))
        return hosts


if __name__ == "__main__":
    url = sys.argv[1]
    user = sys.argv[2]
    password = sys.argv[3]
    session = Session(url)
    session.login(user, password)

