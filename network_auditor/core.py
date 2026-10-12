"""Offline inventory checks; no effective-policy or reachability claims."""
import ipaddress
from opsec_reports.core import ReportError,make_report
from opsec_reports.adapters import result
VERSION='0.1.0a1'
UNSAFE={'telnet','http','snmpv1','snmpv2c','ftp'}
PROTECTED={'ssh','https','snmpv3','winrm-https'}
def require(ok):
 if not ok:raise ReportError('invalid_network_input')
def exact(obj,names):require(isinstance(obj,dict) and set(obj)==set(names))
def networks(value,nullable=True):
 if value is None and nullable:return None
 require(isinstance(value,list) and 0<len(value)<=128)
 out=[]
 for cidr in value:
  require(isinstance(cidr,str) and '/' in cidr and len(cidr)<=49)
  try:net=ipaddress.ip_network(cidr,strict=True)
  except ValueError:raise ReportError('invalid_cidr') from None
  require(net not in out);out.append(net)
 return out
def trusted(net,allowed):
 pieces=[n for n in allowed if n.version==net.version]
 return any(net.subnet_of(n) for n in ipaddress.collapse_addresses(pieces))
def wildcard(nets):
 return {version for version in [4,6] if any(n.prefixlen==0 for n in ipaddress.collapse_addresses([x for x in nets if x.version==version]))}
def assess(data,observed_at,max_rules=1000):
 require(type(max_rules) is int and 1<=max_rules<=1000)
 exact(data,['schema_version','scope','synthetic','semantics','trusted_sources','rules'])
 require(data['schema_version']=='network-inventory-1.0' and data['semantics']=='rule-inventory')
 require(isinstance(data['scope'],str) and 0<len(data['scope'])<=128 and type(data['synthetic']) is bool)
 allowed=networks(data['trusted_sources'],nullable=False)
 require(isinstance(data['rules'],list) and 0<len(data['rules'])<=max_rules)
 records=[];seen=set()
 for rule in data['rules']:
  exact(rule,['id','enabled','action','sources','destinations','protocol','ports','management','management_service','significant','logging'])
  require(isinstance(rule['id'],str) and 0<len(rule['id'])<=128 and rule['id'] not in seen);seen.add(rule['id'])
  for field in ['enabled','management','significant','logging']:require(rule[field] is None or type(rule[field]) is bool)
  require(rule['action'] in ['allow','deny','unknown'] and rule['protocol'] in ['tcp','udp','any','unknown'])
  src=networks(rule['sources']);dst=networks(rule['destinations']);ports=rule['ports']
  require(ports is None or ports=='any' or (isinstance(ports,list) and 0<len(ports)<=256 and all(type(p) is int and 1<=p<=65535 for p in ports)))
  if isinstance(ports,list):require(len(set(ports))==len(ports))
  service=rule['management_service'];require(service is None or (isinstance(service,str) and 0<len(service)<=40))
  if rule['enabled'] is False or rule['action']=='deny':states=['not_applicable']*4
  elif rule['enabled'] is None or rule['action']=='unknown':states=['not_tested']*4
  else:
   management=rule['management'];significant=rule['significant']
   access='not_applicable' if management is False else 'not_tested' if management is None or src is None else 'pass' if all(trusted(n,allowed) for n in src) else 'fail'
   broad='not_tested' if src is None or dst is None or ports is None or rule['protocol']=='unknown' else 'fail' if bool(wildcard(src)&wildcard(dst)) and ports=='any' else 'pass'
   protected='not_applicable' if management is False else 'not_tested' if management is None or service not in UNSAFE|PROTECTED else 'fail' if service in UNSAFE else 'pass'
   logging='not_applicable' if significant is False else 'not_tested' if significant is None or rule['logging'] is None else 'pass' if rule['logging'] else 'fail'
   states=[access,broad,protected,logging]
  for i,status in enumerate(states,1):
   severity={1:'critical',2:'high',3:'high',4:'medium'}[i] if status=='fail' else 'info'
   record=result(f'NET-00{i}',rule['id'],status,severity);record['message']='Network inventory check '+status;records.append(record)
 return make_report('network-config-opsec-auditor',VERSION,'network-inventory-1.0',data['scope'],observed_at,data['synthetic'],records)
