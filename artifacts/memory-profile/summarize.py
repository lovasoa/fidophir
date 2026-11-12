from pathlib import Path
import re,json
base=Path(__file__).resolve().parent
for name in ['profile.log','native-profile.log']:
 records=[];current=None
 for line in (base/name).read_text().splitlines():
  m=re.match(r'PROFILE (\S+) rust_live=(\d+) rust_peak=(\d+) rust_count=(\d+) glibc=MallInfo \{(.*)\}',line)
  if m:
   label,live,peak,count,mi=m.groups()
   current={'stage':label,'rust_live_bytes':int(live),'rust_peak_bytes':int(peak),'rust_live_allocations':int(count),'glibc':{k:int(v) for k,v in re.findall(r'(\w+): (\d+)',mi)},'smaps_kib':{}}
   records.append(current)
  elif line.startswith('SMAPS') or line.startswith('MILESTONE'):current=None
  elif current:
   m=re.match(r'([\w_]+):\s+(\d+) kB',line)
   if m:current['smaps_kib'][m[1]]=int(m[2])
 (base/(name+'.json')).write_text(json.dumps(records,indent=2))
 print(name,len(records))
 for d in records:
  if not d['stage'].startswith('command_'):
   print(d['stage'],'rust KiB',round(d['rust_live_bytes']/1024,2),'glibc used KiB',round(d['glibc']['uordblks']/1024,2),'glibc free KiB',round(d['glibc']['fordblks']/1024,2),'anonymous KiB',d['smaps_kib'].get('Anonymous'),'PSS KiB',d['smaps_kib'].get('Pss'))
 if records:
  print('last',records[-1]['stage'],records[-1]['rust_live_bytes'],records[-1]['glibc']['uordblks'])
