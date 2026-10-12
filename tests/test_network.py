import copy,json,subprocess,sys,tempfile,unittest
from pathlib import Path
from opsec_reports.core import ReportError,outcome
from network_auditor.core import assess
NOW='2026-10-12T00:00:00Z'
def fixture():
 return {'schema_version':'network-inventory-1.0','scope':'synthetic-network','synthetic':True,'semantics':'rule-inventory','trusted_sources':['10.0.0.0/24'],'rules':[{'id':'synthetic-management','enabled':True,'action':'allow','sources':['10.0.0.0/25'],'destinations':['192.0.2.1/32'],'protocol':'tcp','ports':[22],'management':True,'management_service':'ssh','significant':True,'logging':True}]}
class NetworkTests(unittest.TestCase):
 def test_positive(self):self.assertEqual(outcome(assess(fixture(),NOW)),0)
 def test_untrusted_management(self):
  d=fixture();d['rules'][0]['sources']=['0.0.0.0/0'];self.assertEqual(assess(d,NOW)['results'][0]['status'],'fail')
 def test_any_any(self):
  d=fixture();d['rules'][0].update(sources=['0.0.0.0/0'],destinations=['0.0.0.0/0'],protocol='any',ports='any');self.assertEqual(assess(d,NOW)['results'][1]['status'],'fail')
 def test_any_any_restricted_port(self):
  d=fixture();d['rules'][0].update(sources=['0.0.0.0/0'],destinations=['0.0.0.0/0'],protocol='any',ports=[22]);self.assertEqual(assess(d,NOW)['results'][1]['status'],'pass')
 def test_unsafe_services(self):
  for service in ['telnet','http','snmpv1','snmpv2c','ftp']:
   d=fixture();d['rules'][0]['management_service']=service;self.assertEqual(assess(d,NOW)['results'][2]['status'],'fail')
 def test_unknown_service(self):
  d=fixture();d['rules'][0]['management_service']='vendor-custom';self.assertEqual(assess(d,NOW)['results'][2]['status'],'not_tested')
 def test_logging(self):
  d=fixture();d['rules'][0]['logging']=False;self.assertEqual(assess(d,NOW)['results'][3]['status'],'fail')
 def test_unknown_each(self):
  for field,index in [('sources',0),('destinations',1),('management_service',2),('logging',3)]:
   d=fixture();d['rules'][0][field]=None;self.assertEqual(assess(d,NOW)['results'][index]['status'],'not_tested')
 def test_disabled_and_deny(self):
  for key,value in [('enabled',False),('action','deny')]:
   d=fixture();d['rules'][0][key]=value;self.assertEqual({r['status'] for r in assess(d,NOW)['results']},{'not_applicable'})
 def test_unknown_action(self):
  d=fixture();d['rules'][0]['action']='unknown';self.assertEqual(outcome(assess(d,NOW)),2)
 def test_ipv6(self):
  d=fixture();d['trusted_sources']=['2001:db8::/32'];d['rules'][0]['sources']=['2001:db8:1::/48'];self.assertEqual(assess(d,NOW)['results'][0]['status'],'pass');d['rules'][0]['sources']=['::/0'];self.assertEqual(assess(d,NOW)['results'][0]['status'],'fail')
 def test_trust_union(self):
  d=fixture();d['trusted_sources']=['10.0.0.0/25','10.0.0.128/25'];d['rules'][0]['sources']=['10.0.0.0/24'];self.assertEqual(assess(d,NOW)['results'][0]['status'],'pass')
 def test_invalid_cidr(self):
  for value in ['10.0.0.1/24','10.0.0.1','hostname.invalid','999.1.1.1/32']:
   d=fixture();d['rules'][0]['sources']=[value]
   with self.assertRaises(ReportError):assess(d,NOW)
 def test_invalid_ports(self):
  for value in [[True],[0],[65536],[22,22],'22']:
   d=fixture();d['rules'][0]['ports']=value
   with self.assertRaises(ReportError):assess(d,NOW)
 def test_invalid_flags(self):
  for field in ['management','logging','enabled','significant']:
   d=fixture();d['rules'][0][field]=1
   with self.assertRaises(ReportError):assess(d,NOW)
 def test_extra_field(self):
  d=fixture();d['rules'][0]['credential']='synthetic'
  with self.assertRaises(ReportError):assess(d,NOW)
 def test_duplicate_id(self):
  d=fixture();d['rules']*=2
  with self.assertRaises(ReportError):assess(d,NOW)
 def test_empty(self):
  d=fixture();d['rules']=[]
  with self.assertRaises(ReportError):assess(d,NOW)
 def test_budget(self):
  d=fixture();other=copy.deepcopy(d['rules'][0]);other['id']='other';d['rules'].append(other)
  with self.assertRaises(ReportError):assess(d,NOW,max_rules=1)
 def test_unsupported_semantics(self):
  d=fixture();d['semantics']='effective-policy'
  with self.assertRaises(ReportError):assess(d,NOW)
 def test_cli_output_collision(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'in.json';p.write_text(json.dumps(fixture()),encoding='utf-8');args=[sys.executable,'-m','network_auditor',str(p),'--format','neutral-json-v1','--observed-at',NOW,'--output',str(Path(tmp)/'out.json')]
   for code in [0,3]:
    r=subprocess.run(args,capture_output=True,text=True,timeout=20);self.assertEqual(r.returncode,code,r.stdout+r.stderr)
 def test_cli_invalid_no_echo(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'bad.json';p.write_text('{"SENSITIVE_MARKER":NaN}',encoding='utf-8');r=subprocess.run([sys.executable,'-m','network_auditor',str(p),'--format','neutral-json-v1','--observed-at',NOW,'--output',str(Path(tmp)/'out.json')],capture_output=True,text=True,timeout=20);self.assertEqual(r.returncode,3);self.assertNotIn('SENSITIVE_MARKER',r.stdout+r.stderr)

 def test_cross_family_wildcards_not_any_any(self):
  d=fixture();d['rules'][0].update(sources=['0.0.0.0/0'],destinations=['::/0'],protocol='any',ports='any');self.assertEqual(assess(d,NOW)['results'][1]['status'],'pass')
 def test_tcp_any_any(self):
  d=fixture();d['rules'][0].update(sources=['0.0.0.0/0'],destinations=['0.0.0.0/0'],protocol='tcp',ports='any');self.assertEqual(assess(d,NOW)['results'][1]['status'],'fail')
