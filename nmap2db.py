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
table_key = ''
table_elem_key = ''
table_elem_text = ''
script_elem_key = ''
script_elem_text = ''
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

######################################
## XML parse
######################################
  tree = ET.parse(args.file)

except Exception as error:
  print('Error: ' + str(error))
  sys.exit(1)

root = tree.getroot()
nmaprun_scanner = root.get('scanner')
nmaprun_args = root.get('args')
nmaprun_start = root.get('start')
nmaprun_startstr = root.get('startstr')
nmaprun_version = root.get('version')
nmaprun_profile_name = root.get('profile_name')
nmaprun_xmloutputversion = root.get('xmloutputversion')

for scaninfo in root.findall('scaninfo'):
  scaninfo_type = scaninfo.get('type')
  scaninfo_scanflags = scaninfo.get('scanflags')
  scaninfo_protocol = scaninfo.get('protocol')
  scaninfo_numservices = scaninfo.get('numservices')
  scaninfo_services = scaninfo.get('services')

for verbose in root.findall('verbose'):
  verbose_level = verbose.get('level')

for debugging in root.findall('debugging'):
  debugging_level = debugging.get('level')

for runstats in root.findall('runstats'):

  for finished in runstats.findall('finished'):
    finished_time = finished.get('time')
    finished_timestr = finished.get('timestr')
    finished_elapsed = finished.get('elapsed')
    finished_summary = finished.get('summary')
    finished_exit = finished.get('exit')
    finished_errormsg = finished.get('errormsg')

  for hosts in runstats.findall('hosts'):
    hosts_up = hosts.get('up')
    hosts_down = hosts.get('down')
    hosts_total = hosts.get('total')

for host in root.findall('host'):
  host_starttime = host.get('starttime')
  host_endtime = host.get('endtime')
  host_comment = host.get('comment')

  for status in host.findall('status'):
    status_state = status.get('state')
    status_reason = status.get('reason')
    status_reason_ttl = status.get('reason_ttl')

  for address in host.findall('address'):
    address_addr = address.get('addr')
    address_addrtype = address.get('addrtype')
    address_vendor = address.get('vendor')

  for smurf in host.findall('smurf'):
    smurf_responses = smurf.get('responses')

  for distance in host.findall('distance'):
    distance_value = distance.get('value')

  for uptime in host.findall('uptime'):
    uptime_seconds = uptime.get('seconds')
    uptime_lastboot = uptime.get('lastboot')

  for tcpsequence in host.findall('tcpsequence'):
    tcpsequence_index = tcpsequence.get('index')
    tcpsequence_difficulty = tcpsequence.get('difficulty')
    tcpsequence_values = tcpsequence.get('values')

  for ipidsequence in host.findall('ipidsequence'):
    ipidsequence_class = ipidsequence.get('class')
    ipidsequence_values = ipidsequence.get('values')

  for tcptssequence in host.findall('tcptssequence'):
    tcptssequence_class = tcptssequence.get('class')
    tcptssequence_values = tcptssequence.get('values')

  for trace in host.findall('trace'):
    trace_proto = trace.get('proto')
    trace_port = trace.get('port')

    for hop in trace.findall('hop'):
      hop_ttl = hop.get('ttl')
      hop_rtt = hop.get('rtt')
      hop_ipaddr = hop.get('ipaddr')
      hop_host = hop.get('host')

  for hostnames in host.findall('hostnames'):

    for ports in host.findall('ports'):

      for times in ports.findall('times'):
        times_srtt = times.get('srtt')
        times_rttvar = times.get('rttvar')
        times_to = times.get('to')

      for extraports in ports.findall('extraports'):
        extraports_state = extraports.get('state')
        extraports_count = extraports.get('count')

        for extrareasons in extraports.findall('extrareasons'):
          extrareasons_reason = extrareasons.get('reason')
          extrareasons_count = extrareasons.get('count')

      for hostname in hostnames.findall('hostname'):
        hostname_name = hostname.get('name')
        hostname_type = hostname.get('type')

        for os in host.findall('os'):

          for portused in os.findall('portused'):
            portused_state = portused.get('state')
            portused_proto = portused.get('proto')
            portused_portid = portused.get('id')

          for osmatch in os.findall('osmatch'):
            osmatch_name = osmatch.get('name')
            osmatch_accuracy = osmatch.get('accuracy')
            osmatch_line = osmatch.get('line')

            for osclass in osmatch.findall('osclass'):
              osclass_vendor = osclass.get('vendor')
              osclass_osgen = osclass.get('osgen')
              osclass_type = osclass.get('type')
              osclass_accuracy = osclass.get('accuracy')
              osclass_osfamily = osclass.get('osfamily')

              for cpe in osclass.findall('cpe'):
                osclass_cpe_text = cpe.text

          for osfingerprint in os.findall('fingerprint'):
            osfingerprint_fingerprint = osfingerprint.get('fingerprint')




        for port in ports.findall('port'):
          port_protocol = port.get('protocol')
          port_portid = port.get('portid')

          for state in port.findall('state'):
            state_state = state.get('state')
            state_reason = state.get('reason')
            state_reason_ttl = state.get('reason_ttl')
            state_reason_ip = state.get('reason_ip')

          for owner in port.findall('owner'):
            owner_name = owner.get('name')

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

            for cpe in service.findall('cpe'):
              service_cpe_text = cpe.text

          for script in port.findall('script'):
            script_id = script.get('id')
            script_output = script.get('output')

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
            output_type]
          results_array.append(variables_array)

######################################
## SQLite stuff
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



