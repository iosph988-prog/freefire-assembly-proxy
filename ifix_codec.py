import struct,collections,io,sys,json
from pathlib import Path
MAGIC=0x66a319b20db4a2cb
class Reader:
 def __init__(self,d,off=0):self.data=d;self.o=off
 def take(self,n):
  if n<0 or self.o+n>len(self.data): raise ValueError(f'read overflow offset={self.o} len={n} total={len(self.data)}')
  b=self.data[self.o:self.o+n];self.o+=n;return b
 def i(self):return struct.unpack('<i',self.take(4))[0]
 def u(self):return struct.unpack('<Q',self.take(8))[0]
 def b(self):return self.take(1)[0]
 def string(self):
  n=0
  for i in range(5):
   byte=self.b();n|=(byte&0x7f) << (i*7)
   if byte<128: break
  else: raise ValueError('7 bit length exceeds limit')
  return self.take(n).decode('utf-8')
 def count(self,label,max_=200000):
  v=self.i()
  if not 0<=v<=max_:raise ValueError(f'{label} invalid count {v} at offset {self.o-4}')
  return v

def parse_method(r,externtypes):
 generic=r.b()
 if generic not in(0,1):raise ValueError('method generic invalid '+str(generic))
 idx=r.i();typeName=externtypes[idx]
 name=r.string()
 if generic:
  num=r.count('generic arguments',300)
  argids=[r.i() for _ in range(num)];args=[externtypes[idx] for idx in argids]
  param_num=r.count('generic param count',300)
  params=[]; paramIds=[]
  for _ in range(param_num):
   g=r.b(); idOrStr=r.string() if g else r.i(); paramIds.append((g,idOrStr));params.append((g, idOrStr if g else externtypes[idOrStr]))
 else:
  args=[];argids=[];num=r.count('parameter count',200);paramIds=[r.i() for _ in range(num)];params=[externtypes[idx] for idx in paramIds]
 return {'generic':generic,'type':idx,'method':name,'args':args,'params':params,'qualified':typeName,'argids':argids,'paramIds':paramIds}

def parse_ifix(data,start=0):
 r=Reader(data,start)
 h=r.u();assert h==MAGIC,('invalid magic',h)
 bridge=r.string();n=r.count('externTypeCount');externtypes=[r.string() for _ in range(n)];
 print("start",start,"at",r.o,"types",n);code_offset=r.o
 nmethods=r.count('methodCount',100000);methods=[]
 for method_idx in range(nmethods):
  code_count=r.count('codeSize',2000000)
  instrs=[struct.unpack('<ii',r.take(8)) for _ in range(code_count)]
  excnum=r.count('exceptions',100000)
  handlers=[struct.unpack('<iiiiii',r.take(24)) for _ in range(excnum)]
  methods.append({'code':instrs,'handlers':handlers})
 nr=r.count('externMethodCount');extm=[parse_method(r,externtypes) for _ in range(nr)]
 ns=r.count('internStringsCount');strings=[r.string() for _ in range(ns)]
 nf=r.count('fieldInfos');fields=[]
 for _ in range(nf):
  is_new=r.b();tid=r.i();name=r.string()
  extra=(r.i(),r.i()) if is_new else None
  fields.append({'is_new':is_new,'type':tid,'name':name,'extra':extra})
 static_n=r.count('staticFieldTypes');statics=[(r.i(),r.i()) for _ in range(static_n)]
 print('statics end',r.o,'statics',static_n)
 anonstart=r.o
 an=r.count('anonymousStoreyInfo');anon=[]
 if an:
  wrapper_anchor=data.find(b'IFix.WrappersManagerImpl',r.o)
  if wrapper_anchor==-1:raise ValueError('Missing wrapper anchor')
  r.o=wrapper_anchor-1
 anon_raw=data[anonstart:r.o]
 wrapper=r.string();assembly=r.string()
 extra=r.b();fix_n=r.count('fixCount');fixes=[]
 for k in range(fix_n):
  mm=parse_method(r,externtypes);methodId=r.i()
  fixes.append({'method':mm,'id':methodId})
 newclass_n=r.count('newclasscount');newclasses=[r.string() for _ in range(newclass_n)]
 return {'offset':start,'length':r.o-start,'end':r.o,'bridge':bridge,'types':externtypes,'methods':methods,'externMethods':extm,'strings':strings,'fields':fields,'statics':statics,'anon':anon,'anon_count':an,'anon_raw':anon_raw,'wrapper':wrapper,'assembly':assembly,'fixes':fixes,'newclasses':newclasses,'code_offset':code_offset,'extra':extra}

def brief(p):
 from collections import Counter
 return {'length':p['length'],'bridge':p['bridge'],'types':len(p['types']),'methods':len(p['methods']),'code_sizes':[len(x['code']) for x in p['methods']],'externMethods':len(p['externMethods']),'strings':p['strings'],'fields':len(p['fields']),'statics':len(p['statics']),'anon':p['anon_count'],'wrapper':p['wrapper'],'assembly':p['assembly'],'fixes':[(m['id'],m['method']['qualified'].split(',')[0]+'::'+m['method']['method']) for m in p['fixes']],'newclasses':p['newclasses']}

if __name__=='__main__':
 f1=Path('/mnt/data/Assembly-CSharp-patch(5).bytes'); f2=Path('/mnt/data/assembly-csharp-patch-OFFICIAL-121840.bytes')
 for f,start in [(f1,0),(f2,2768)]:
  try:
   p=parse_ifix(f.read_bytes(),start)
   with open('/mnt/data/'+('base' if start==0 else 'clean')+'_ifix_summary.json','w') as outf:json.dump(brief(p),outf,ensure_ascii=False,indent=2)
   sm=brief(p); print(f.name,'baseOffset',start,'byte length',len(f.read_bytes()),'IFix length',sm['length'],'end',p['end'],'types',sm['types'],'methods',sm['methods'],'extern methods',sm['externMethods'],'fixes',len(sm['fixes']),'fields',sm['fields'],'strings',len(sm['strings']),'anon',sm['anon'])
   print('Bridges',sm['bridge'],sm['wrapper'],sm['assembly'],'newclasses',sm['newclasses']); print('fixes:',sm['fixes'][:70]); print('strings sample:',sm['strings'][:35]);print('methods sizes sample:',sm['code_sizes'][:15])
  except Exception as e:
   print('FAILED',f,e,'at maybe',r.o if 'r' in globals() else 'unknown');raise
