#!/usr/bin/env python3
import sys
import argparse
import sqlite3
import xml.etree.ElementTree as ET

#####################################
## Variable Initialization
#####################################
variables_array = []
results_array = []
nmaprun_scanner = ''
nmaprun_args = ''
nmaprun_start = ''
nmaprun_startstr = ''
nmaprun_version = ''
nmaprun_profile_name = ''
nmaprun_xmloutputversion = ''
scaninfo_type = ''
scaninfo_scanflags = ''
scaninfo_protocol = ''
scaninfo_numservices = ''
scaninfo_services = ''
verbose_level = ''
debugging_level = ''
finished_time = ''
finished_timestr = ''
finished_elapsed = ''
finished_summary = ''
finished_exit = ''
finished_errormsg = ''
hosts_up = ''
hosts_down = ''
hosts_total = ''
host_starttime = ''
host_endtime = ''
host_comment = ''
status_state = ''
status_reason = ''
status_reason_ttl = ''
address_addr = ''
address_addrtype = ''
address_vendor = ''
times_srtt = ''
times_rttvar = ''
times_to = ''
smurf_responses = ''
extraports_state = ''
extraports_count = ''
extrareasons_reason = ''
extrareasons_count = ''
hostname_name = ''
hostname_type = ''
port_protocol = ''
port_portid = ''
state_state = ''
state_reason = ''
state_reason_ttl = ''
state_reason_ip = ''
owner_name = ''
service_name = ''
service_conf = ''
service_method = ''
service_version = ''
service_product = ''
service_extrainfo = ''
service_tunnel = ''
service_proto = ''
service_rpcnum = ''
service_lowver = ''
service_highver = ''
service_hostname = ''
service_ostype = ''
service_devicetype = ''
service_servicefp = ''
service_cpe_text = ''
script_id = ''
script_output = ''
portused_state = ''
portsused_proto = ''
portsused_portid = ''
osclass_vendor = ''
osclass_osgen = ''
osclass_type = ''
osclass_accuracy = ''
osclass_osfamily = ''
osclass_cpe_text = ''
osmatch_name = ''
osmatch_accuracy = ''
osmatch_line = ''
osfingerprint_fingerprint = ''
distance_value = ''
uptime_seconds = ''
uptime_lastboot = ''
tcpsequence_index = ''
tcpsequence_difficulty = ''
tcpsequence_values = ''
ipidsequence_class = ''
ipidsequence_values = ''
tcptssequence_class = ''
tcptssequence_values = ''
trace_proto = ''
trace_port = ''
hop_ttl = ''
hop_rtt = ''
hop_ipaddr = ''
hop_host = ''
output_type = ''

######################################
## Help menu/ argsparse
######################################
try:
  parser = argparse.ArgumentParser(description='Convert nmap XML data to sqlite3 database.')
  parser.add_argument('file', type=open, help='file to be parsed by script')
  args = parser.parse_args()
  tree = ET.parse(args.file)

except Exception as error:
  print('Error: ' + str(error))
  sys.exit(1)

######################################
## XML parse
######################################
root = tree.getroot()
nmaprun_scanner = ''
nmaprun_args = ''
nmaprun_start = ''
nmaprun_startstr = ''
nmaprun_version = ''
nmaprun_profile_name = ''
nmaprun_xmloutputversion = ''
nmaprun_scanner = root.get('scanner')
nmaprun_args = root.get('args')
nmaprun_start = root.get('start')
nmaprun_startstr = root.get('startstr')
nmaprun_version = root.get('version')
nmaprun_profile_name = root.get('profile_name')
nmaprun_xmloutputversion = root.get('xmloutputversion')

scaninfo_type = ''
scaninfo_scanflags = ''
scaninfo_protocol = ''
scaninfo_numservices = ''
scaninfo_services = ''
for scaninfo in root.findall('scaninfo'):
  scaninfo_type = scaninfo.get('type')
  scaninfo_scanflags = scaninfo.get('scanflags')
  scaninfo_protocol = scaninfo.get('protocol')
  scaninfo_numservices = scaninfo.get('numservices')
  scaninfo_services = scaninfo.get('services')

verbose_level = ''
for verbose in root.findall('verbose'):
  verbose_level = verbose.get('level')

debugging_level = ''
for debugging in root.findall('debugging'):
  debugging_level = debugging.get('level')

for runstats in root.findall('runstats'):
  finished_time = ''
  finished_timestr = ''
  finished_elapsed = ''
  finished_summary = ''
  finished_exit = ''
  finished_errormsg = ''
  for finished in runstats.findall('finished'):
    finished_time = finished.get('time')
    finished_timestr = finished.get('timestr')
    finished_elapsed = finished.get('elapsed')
    finished_summary = finished.get('summary')
    finished_exit = finished.get('exit')
    finished_errormsg = finished.get('errormsg')

  hosts_up = ''
  hosts_down = ''
  hosts_total = ''
  for hosts in runstats.findall('hosts'):
    hosts_up = hosts.get('up')
    hosts_down = hosts.get('down')
    hosts_total = hosts.get('total')

output_type = ''
for output in root.findall('output'):
  output_type = output.get('type')

host_starttime = ''
host_endtime = ''
host_comment = ''
for host in root.findall('host'):
  host_starttime = host.get('starttime')
  host_endtime = host.get('endtime')
  host_comment = host.get('comment')

  status_state = ''
  status_reason = ''
  status_reason_ttl = ''
  for status in host.findall('status'):
    status_state = status.get('state')
    status_reason = status.get('reason')
    status_reason_ttl = status.get('reason_ttl')

  address_addr = ''
  address_addrtype = ''
  address_vendor = ''
  for address in host.findall('address'):
    address_addr = address.get('addr')
    address_addrtype = address.get('addrtype')
    address_vendor = address.get('vendor')

  smurf_responses = ''
  for smurf in host.findall('smurf'):
    smurf_responses = smurf.get('responses')

  distance_value = ''
  for distance in host.findall('distance'):
    distance_value = distance.get('value')

  uptime_seconds = ''
  uptime_lastboot = ''
  for uptime in host.findall('uptime'):
    uptime_seconds = uptime.get('seconds')
    uptime_lastboot = uptime.get('lastboot')

  tcpsequence_index = ''
  tcpsequence_difficulty = ''
  tcpsequence_values = ''
  for tcpsequence in host.findall('tcpsequence'):
    tcpsequence_index = tcpsequence.get('index')
    tcpsequence_difficulty = tcpsequence.get('difficulty')
    tcpsequence_values = tcpsequence.get('values')

  ipidsequence_class = ''
  ipidsequence_values = ''
  for ipidsequence in host.findall('ipidsequence'):
    ipidsequence_class = ipidsequence.get('class')
    ipidsequence_values = ipidsequence.get('values')

  tcptssequence_class = ''
  tcptssequence_values = ''
  for tcptssequence in host.findall('tcptssequence'):
    tcptssequence_class = tcptssequence.get('class')
    tcptssequence_values = tcptssequence.get('values')

  trace_proto = ''
  trace_port = ''
  for trace in host.findall('trace'):
    trace_proto = trace.get('proto')
    trace_port = trace.get('port')

    hop_ttl = ''
    hop_rtt = ''
    hop_ipaddr = ''
    hop_host = ''
    for hop in trace.findall('hop'):
      hop_ttl += str(hop.get('ttl')) + '\n'
      hop_rtt += str(hop.get('rtt')) + '\n'
      hop_ipaddr += str(hop.get('ipaddr')) + '\n'
      hop_host += str(hop.get('host')) + '\n'

  for hostnames in host.findall('hostnames'):
    hostname_name = ''
    hostname_type = ''
    for hostname in hostnames.findall('hostname'):
      hostname_name += str(hostname.get('name')) + '\n'
      hostname_type += str(hostname.get('type')) + '\n'

  for os in host.findall('os'):
    portused_state = ''
    portsused_proto = ''
    portsused_portid = ''
    for portused in os.findall('portused'):
      portused_state = portused.get('state')
      portused_proto = portused.get('proto')
      portused_portid = portused.get('id')

    osmatch_name = ''
    osmatch_accuracy = ''
    osmatch_line = ''
    for osmatch in os.findall('osmatch'):
      osmatch_name += str(osmatch.get('name')) + '\n'
      osmatch_accuracy += str(osmatch.get('accuracy')) + '\n'
      osmatch_line += str(osmatch.get('line')) + '\n'

      osclass_vendor = ''
      osclass_osgen = ''
      osclass_type = ''
      osclass_accuracy = ''
      osclass_osfamily = ''
      osclass_cpe_text = ''
      for osclass in osmatch.findall('osclass'):
        osclass_vendor += str(osclass.get('vendor')) + '\n'
        osclass_osgen += str(osclass.get('osgen')) + '\n'
        osclass_type += str(osclass.get('type')) + '\n'
        osclass_accuracy += str(osclass.get('accuracy')) + '\n'
        osclass_osfamily += str(osclass.get('osfamily')) + '\n'

        for cpe in osclass.findall('cpe'):
          osclass_cpe_text = cpe.text

    osfingerprint_fingerprint = ''
    for osfingerprint in os.findall('fingerprint'):
      osfingerprint_fingerprint += str(osfingerprint.get('fingerprint')) + '\n'

  for ports in host.findall('ports'):
    times_srtt = ''
    times_rttvar = ''
    times_to = ''
    for times in ports.findall('times'):
      times_srtt = times.get('srtt')
      times_rttvar = times.get('rttvar')
      times_to = times.get('to')

    extraports_state = ''
    extraports_count = ''
    for extraports in ports.findall('extraports'):
      extraports_state = extraports.get('state')
      extraports_count = extraports.get('count')

      extrareasons_reason = ''
      extrareasons_count = ''
      for extrareasons in extraports.findall('extrareasons'):
        extrareasons_reason = extrareasons.get('reason')
        extrareasons_count = extrareasons.get('count')

    port_protocol = ''
    port_portid = ''
    for port in ports.findall('port'):
      port_protocol = port.get('protocol')
      port_portid = port.get('portid')

      state_state = ''
      state_reason = ''
      state_reason_ttl = ''
      state_reason_ip = ''
      for state in port.findall('state'):
        state_state = state.get('state')
        state_reason = state.get('reason')
        state_reason_ttl = state.get('reason_ttl')
        state_reason_ip = state.get('reason_ip')

      owner_name = ''
      for owner in port.findall('owner'):
        owner_name = owner.get('name')

      service_name = ''
      service_conf = ''
      service_method = ''
      service_version = ''
      service_product = ''
      service_extrainfo = ''
      service_tunnel = ''
      service_proto = ''
      service_rpcnum = ''
      service_lowver = ''
      service_highver = ''
      service_hostname = ''
      service_ostype = ''
      service_devicetype = ''
      service_servicefp = ''
      service_cpe_text = ''
      for service in port.findall('service'):
        service_name = service.get('name')
        service_conf = service.get('conf')
        service_method = service.get('method')
        service_version = service.get('version')
        service_product = service.get('product')
        service_extrainfo = service.get('extrainfo')
        service_tunnel = service.get('tunnel')
        service_proto = service.get('proto')
        service_rpcnum = service.get('rpcnum')
        service_lowver = service.get('lowver')
        service_highver = service.get('highver')
        service_hostname = service.get('hostname')
        service_ostype = service.get('ostype')
        service_devicetype = service.get('devicetype')
        service_servicefp = service.get('servicefp')

        service_cpe_text = ''
        for cpe in service.findall('cpe'):
          service_cpe_text += cpe.text + '\n'

        script_id = ''
        script_output = ''
        for script in port.findall('script'):
          script_id += str(script.get('id')) + '\n'
          script_output += str(script.get('output')) + '\n'

        variables_array = [nmaprun_start,
            nmaprun_startstr,
            nmaprun_version,
            nmaprun_profile_name,
            nmaprun_xmloutputversion,
            scaninfo_type,
            scaninfo_scanflags,
            scaninfo_protocol,
            scaninfo_numservices,
            scaninfo_services,
            verbose_level,
            debugging_level,
            finished_time,
            finished_timestr,
            finished_elapsed,
            finished_summary,
            finished_exit,
            finished_errormsg,
            hosts_up,
            hosts_down,
            hosts_total,
            host_starttime,
            host_endtime,
            host_comment,
            status_state,
            status_reason,
            status_reason_ttl,
            address_addr,
            address_addrtype,
            address_vendor,
            times_srtt,
            times_rttvar,
            times_to,
            smurf_responses,
            extraports_state,
            extraports_count,
            extrareasons_reason,
            extrareasons_count,
            hostname_name.rstrip(),
            hostname_type.rstrip(),
            port_protocol,
            port_portid,
            state_state,
            state_reason,
            state_reason_ttl,
            state_reason_ip,
            owner_name,
            service_name,
            service_conf,
            service_method,
            service_version,
            service_product,
            service_extrainfo,
            service_tunnel,
            service_proto,
            service_rpcnum,
            service_lowver,
            service_highver,
            service_hostname,
            service_ostype,
            service_devicetype,
            service_servicefp,
            service_cpe_text.rstrip(),
            script_id,
            script_output,
            portused_state,
            portsused_proto,
            portsused_portid,
            osclass_vendor.rstrip(),
            osclass_osgen.rstrip(),
            osclass_type.rstrip(),
            osclass_accuracy.rstrip(),
            osclass_osfamily.rstrip(),
            osclass_cpe_text.rstrip(),
            osmatch_name.rstrip(),
            osmatch_accuracy.rstrip(),
            osmatch_line.rstrip(),
            osfingerprint_fingerprint.rstrip(),
            distance_value,
            uptime_seconds,
            uptime_lastboot,
            tcpsequence_index,
            tcpsequence_difficulty,
            tcpsequence_values,
            ipidsequence_class,
            ipidsequence_values,
            tcptssequence_class,
            tcptssequence_values,
            trace_proto,
            trace_port,
            hop_ttl.rstrip(),
            hop_rtt.rstrip(),
            hop_ipaddr.rstrip(),
            hop_host.rstrip(),
            output_type]
        results_array.append(variables_array)

######################################
## SQLite operations
######################################

conn = sqlite3.connect('databases/nmap2db.db')

try:
  conn.execute('''CREATE TABLE IF NOT EXISTS db(
    nmaprun_start,
    nmaprun_startstr,
    nmaprun_version,
    nmaprun_profile_name,
    nmaprun_xmloutputversion,
    scaninfo_type,
    scaninfo_scanflags,
    scaninfo_protocol,
    scaninfo_numservices,
    scaninfo_services,
    verbose_level,
    debugging_level,
    finished_time,
    finished_timestr,
    finished_elapsed,
    finished_summary,
    finished_exit,
    finished_errormsg,
    hosts_up,
    hosts_down,
    hosts_total,
    host_starttime,
    host_endtime,
    host_comment,
    status_state,
    status_reason,
    status_reason_ttl,
    address_addr,
    address_addrtype,
    address_vendor,
    times_srtt,
    times_rttvar,
    times_to,
    smurf_responses,
    extraports_state,
    extraports_count,
    extrareasons_reason,
    extrareasons_count,
    hostname_name,
    hostname_type,
    port_protocol,
    port_portid,
    state_state,
    state_reason,
    state_reason_ttl,
    state_reason_ip,
    owner_name,
    service_name,
    service_conf,
    service_method,
    service_version,
    service_product,
    service_extrainfo,
    service_tunnel,
    service_proto,
    service_rpcnum,
    service_lowver,
    service_highver,
    service_hostname,
    service_ostype,
    service_devicetype,
    service_servicefp,
    service_cpe_text,
    script_id,
    script_output,
    portused_state,
    portsused_proto,
    portsused_portid,
    osclass_vendor,
    osclass_osgen,
    osclass_type,
    osclass_accuracy,
    osclass_osfamily,
    osclass_cpe_text,
    osmatch_name,
    osmatch_accuracy,
    osmatch_line,
    osfingerprint_fingerprint,
    distance_value,
    uptime_seconds,
    uptime_lastboot,
    tcpsequence_index,
    tcpsequence_difficulty,
    tcpsequence_values,
    ipidsequence_class,
    ipidsequence_values,
    tcptssequence_class,
    tcptssequence_values,
    trace_proto,
    trace_port,
    hop_ttl,
    hop_rtt,
    hop_ipaddr,
    hop_host,
    output_type
   )''')

  conn.executemany("INSERT INTO db values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", results_array)
  conn.commit()
  conn.close()

except Exception as error:
  print('Error: ' + str(error))



