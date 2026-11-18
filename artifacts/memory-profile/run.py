import sys, pathlib, tempfile, subprocess, time, os, json
sys.path.insert(0, str(pathlib.Path('tests').resolve()))
import interop
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.hid import CTAPHID
base=pathlib.Path('artifacts/memory-profile').resolve()
os.environ['TSS2_LOG']='all+NONE'
native=os.environ.get('PROFILE_NATIVE')=='1'
logname='native-profile.log' if native else 'profile.log'
with tempfile.TemporaryDirectory(prefix='fidophir-mem-') as tmp:
 root=pathlib.Path(tmp); (root/'sim').mkdir(mode=0o700); (root/'state').mkdir(mode=0o700)
 port=interop.free_ports(); tcti=f'swtpm:host=127.0.0.1,port={port}'
 with (base/'simulator.log').open('w') as simlog, (base/logname).open('w') as log:
  sim=subprocess.Popen(['swtpm','socket','--tpm2','--tpmstate',f'dir={root}/sim','--server',f'type=tcp,port={port},bindaddr=127.0.0.1','--ctrl',f'type=tcp,port={port+1},bindaddr=127.0.0.1','--flags','not-need-init,startup-clear'],stdout=simlog,stderr=simlog)
  bus=server=None
  if native:
   (root/'mode').write_text('allow'); (root/'events').write_text('')
   address=f'unix:path={root}/bus'
   bus=subprocess.Popen(['dbus-daemon','--session','--nofork','--print-address=1',f'--address={address}'],stdout=subprocess.PIPE,text=True)
   address=bus.stdout.readline().strip()
   server=subprocess.Popen([sys.executable,str(pathlib.Path('tests/desktop.py').resolve()),'--serve',address,str(root)],stdout=subprocess.PIPE,text=True)
   assert server.stdout.readline().strip()=='READY'
   os.environ['DBUS_SYSTEM_BUS_ADDRESS']=address
  pipe=None
  try:
   time.sleep(.3)
   # Redirect instrumented process stderr, keeping the client outside measured process.
   class ProfilePipe(interop.Pipe):
    def __init__(self):
     self.proc=subprocess.Popen([str(pathlib.Path('target/release/memory_profile').resolve()),str(root/'state'),tcti,'native' if native else 'allow'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log)
   pipe=ProfilePipe(); ctap=Ctap2(pipe)
   def mark(label):
    print(label,flush=True); log.write('MILESTONE '+label+'\n'); log.flush()
   mark('initial GetInfo'); ctap.get_info()
   mark('PIN setup'); ClientPin(ctap).set_pin('1234')
   mark('first credential'); first=interop.register(ctap,'1234',b'first')
   mark('first signature'); interop.sign(ctap,'1234',first)
   mark('35s idle after first operation'); pipe.call(CTAPHID.CBOR,b'\xfe')
   mark('trim after first idle'); pipe.call(CTAPHID.CBOR,b'\xfd')
   mark('fill to 300 credentials')
   for i in range(1,300):
    interop.register(ctap,'1234',f'user{i}'.encode())
    if i%50==0: print('credentials',i+1,flush=True)
   mark('100 signatures')
   for i in range(100):interop.sign(ctap,'1234',first)
   mark('35s idle after full store workload'); pipe.call(CTAPHID.CBOR,b'\xfe')
   mark('trim after workload'); pipe.call(CTAPHID.CBOR,b'\xfd')
   pipe.close();pipe=None
  finally:
   if pipe:
    pipe.proc.kill(); pipe.proc.wait()
   sim.terminate();sim.wait(timeout=10)
   for child in [server,bus]:
    if child:child.terminate();child.wait(timeout=10)
print('profile saved:',base/logname)
