/* Security portfolio: all exercises run locally. No analytics or external API calls. */
(() => {
  'use strict';
  const samples = {
    iac: `resource "aws_security_group" "admin" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n\nresource "aws_ebs_volume" "data" {\n  encrypted = false\n}`,
    agent: JSON.stringify({principal: {identity: 'support-agent-01', tenant: 'acme', role: 'support'}, call: {tool: 'read_ticket', arguments: {tenant: 'other-company', ticket_id: 'TKT-104'}}}, null, 2),
    cloud: [
      {eventTime:'2026-10-20T12:01:00Z',eventName:'ConsoleLogin',sourceIPAddress:'198.51.100.12',userIdentity:{arn:'arn:aws:iam::111111111111:user/demo'},responseElements:{ConsoleLogin:'Failure'}},
      {eventTime:'2026-10-20T12:03:00Z',eventName:'ConsoleLogin',sourceIPAddress:'198.51.100.12',userIdentity:{arn:'arn:aws:iam::111111111111:user/demo'},responseElements:{ConsoleLogin:'Failure'}},
      {eventTime:'2026-10-20T12:05:00Z',eventName:'ConsoleLogin',sourceIPAddress:'198.51.100.12',userIdentity:{arn:'arn:aws:iam::111111111111:user/demo'},responseElements:{ConsoleLogin:'Failure'}},
      {eventTime:'2026-10-20T12:09:00Z',eventName:'AttachRolePolicy',sourceIPAddress:'203.0.113.30',userIdentity:{arn:'arn:aws:iam::111111111111:user/admin'},requestParameters:{policyArn:'arn:aws:iam::aws:policy/AdministratorAccess'}}
    ].map(JSON.stringify).join('\n')
  };
  const titles={iac:'Terraform exposure review',agent:'Untrusted agent tool request',cloud:'CloudTrail event correlation'};
  const hints={iac:'Try replacing 0.0.0.0/0 with 10.0.0.0/8.',agent:'Try changing the tenant to acme or tool to delete_customer.',cloud:'Try removing a failed login or editing a policy event.'};
  let active='iac';
  let lastPlainText='';
  const $ = (s)=>document.querySelector(s);
  const $$ = (s)=>Array.from(document.querySelectorAll(s));
  const editor=$('#demo-input');
  const output=$('#demo-output');
  const state=$('#output-state');
  function cleanHcl(src){
    // Browser visualization supports simple literal syntax only. Python CLI has a fuller lexer.
    return src.replace(/\/\*[\s\S]*?\*\//g,'').replace(/^\s*(?:#|\/\/).*$/gm,'');
  }
  function scanTerraform(src){
    const text=cleanHcl(src);
    const findings=[];
    const matches=[...text.matchAll(/resource\s+"(aws_[^"]+)"\s+"([^"]+)"\s*\{/g)];
    for(let i=0;i<matches.length;i++){
      const m=matches[i], from=m.index+m[0].length;
      const end=i+1<matches.length?matches[i+1].index:text.length;
      const block=text.slice(from,end);
      const resource=m[1]+'.'+m[2];
      function add(id,severity,title,fix){findings.push({id,severity,title,detail:resource+' · '+fix});}
      if(m[1]==='aws_security_group' && /cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"/s.test(block) && /from_port\s*=\s*22\b/.test(block) && /to_port\s*=\s*22\b/.test(block))add('IAC-001','critical','Public SSH exposure','Restrict ingress to trusted network ranges.');
      if(['aws_s3_bucket','aws_s3_bucket_acl'].includes(m[1]) && /acl\s*=\s*"public-(read|read-write)"/.test(block))add('IAC-002','high','Public S3 ACL','Use private ACL and Block Public Access.');
      if(m[1]==='aws_db_instance' && /publicly_accessible\s*=\s*true\b/.test(block))add('IAC-004','high','Public RDS instance','Disable public access and restrict network reachability.');
      if(m[1]==='aws_ebs_volume' && /encrypted\s*=\s*false\b/.test(block))add('IAC-005','medium','Encryption disabled','Enable encrypted EBS volumes with managed keys.');
      if(m[1]==='aws_s3_bucket_public_access_block' && /block_public_acls\s*=\s*false\b/.test(block))add('IAC-006','medium','S3 ACL blocking disabled','Enable public access block settings.');
    }
    return findings;
  }
  function agentPolicy(src){
    let data;
    try{data=JSON.parse(src);}catch(err){return [{id:'INPUT',severity:'high',title:'Invalid JSON',detail:err.message}];}
    const actor=data.principal||{},call=data.call||{},tool=call.tool,args=call.arguments;
    const acl={analyst:['read_ticket','search_documents'],support:['read_ticket','search_documents','create_ticket'],admin:['read_ticket','search_documents','create_ticket','close_ticket']};
    const schemas={read_ticket:['tenant','ticket_id'],search_documents:['tenant','query','limit'],create_ticket:['tenant','title','description'],close_ticket:['tenant','ticket_id']};
    let reason='allowed',severity='medium';
    if(typeof tool!=='string'||!(tool in schemas)){reason='tool_not_allowlisted';severity='critical';}
    else if(!args||typeof args!=='object'||Array.isArray(args)||Object.keys(args).some(x=>!schemas[tool].includes(x))){reason='invalid_argument_schema';severity='high';}
    else if(!acl[actor.role]||!acl[actor.role].includes(tool)){reason='role_denied';severity='high';}
    else if(actor.tenant!==args.tenant){reason='cross_tenant_access_denied';severity='critical';}
    else if(Object.values(args).some(v=>typeof v==='string'&&/(?:ignore (?:all |the )?(?:prior|previous|system) instructions|reveal (?:the )?(?:secret|api key|system prompt)|send (?:all )?(?:credentials|keys|secrets) to)/i.test(v))){reason='suspicious_instruction_content';severity='high';}
    else if(tool==='search_documents' && (typeof args.query!=='string'||(args.limit!==undefined&&(!Number.isInteger(args.limit)||args.limit<1||args.limit>20)))){reason='search_bounds_denied';severity='medium';}
    else if(['read_ticket','close_ticket'].includes(tool) && !/^TKT-\d{3,8}$/.test(args.ticket_id||'')){reason='ticket_id_invalid';severity='medium';}
    else if(tool==='create_ticket' && (typeof args.title!=='string'||!args.title.length||args.title.length>120||typeof args.description!=='string'||args.description.length>1000)){reason='ticket_validation_denied';severity='medium';}
    const allowed=reason==='allowed';
    return [{id:allowed?'POLICY-ALLOW':'POLICY-DENY',severity:allowed?'medium':severity,title:allowed?'Tool call authorized':'Tool call denied',detail:`${reason} · role: ${actor.role||'unknown'} · tool: ${tool||'invalid'} · tenant: ${actor.tenant||'unknown'}`,allowed}];
  }
  function cloudDetect(src){
    const events=[];
    for(const [i,line] of src.split('\n').entries()){
      if(!line.trim())continue;
      try{const v=JSON.parse(line);if(v&&v.eventTime&&v.eventName&&v.userIdentity&&v.sourceIPAddress)events.push(v);}catch(err){return [{id:'INPUT',severity:'high',title:`Invalid JSON on line ${i+1}`,detail:err.message}];}
    }
    const findings=[];
    const group=new Map();
    for(const e of events){
      const ip=e.sourceIPAddress,who=e.userIdentity.arn||'unknown';
      if(e.eventName==='ConsoleLogin'&&e.responseElements?.ConsoleLogin==='Failure'){
        const key=who+'|'+ip;if(!group.has(key))group.set(key,[]);
        group.get(key).push(new Date(e.eventTime).getTime());
      }
      if(e.eventName==='AuthorizeSecurityGroupIngress'&&e.requestParameters?.cidrIp==='0.0.0.0/0'&&e.requestParameters?.fromPort===22&&e.requestParameters?.toPort===22)
        findings.push({id:'CLOUD-002',severity:'critical',title:'Public SSH ingress',detail:`${who} · ${ip} · MITRE T1562.007`});
      if(['AttachRolePolicy','AttachUserPolicy'].includes(e.eventName)&&String(e.requestParameters?.policyArn||'').includes('AdministratorAccess'))
        findings.push({id:'CLOUD-003',severity:'high',title:'AdministratorAccess attached',detail:`${who} · ${ip} · MITRE T1098`});
    }
    for(const [key,times] of group){times.sort((a,b)=>a-b);let left=0;
      for(let i=0;i<times.length;i++){while(times[i]-times[left]>600000)left++;
        if(i-left+1>=3){findings.push({id:'CLOUD-001',severity:'high',title:'Repeated failed console logins',detail:`${key.split('|')[1]} · ${i-left+1} failures / 10 minutes · MITRE T1110`});break;}
      }
    }
    return findings;
  }
  const render=(findings)=>{
    output.replaceChildren();
    const allowed=findings.length===1 && findings[0].allowed===true;
    const clear=findings.length===0;
    state.textContent=clear?'PASS':allowed?'ALLOWED':findings.some(f=>f.id==='INPUT')?'INPUT ERROR':'FINDINGS';
    lastPlainText=clear?'No findings in supported rules. This does not prove a configuration is secure.':findings.map(f=>`${f.id} ${f.severity.toUpperCase()} ${f.title}: ${f.detail}`).join('\n');
    const title=document.createElement('h4');title.className='result-title';title.textContent=clear?'No findings from these rules.':allowed?'Action allowed':findings.length===1?'1 result':`${findings.length} results`;output.appendChild(title);
    if(clear){const p=document.createElement('p');p.className='result-success';p.textContent='✓ Supported patterns not detected. Review the full policy and configuration for broader coverage.';output.appendChild(p);return;}
    for(const item of findings){const row=document.createElement('div');row.className='result-row';const top=document.createElement('div');top.className='result-row-head';const label=document.createElement('strong');label.textContent=item.id;const badge=document.createElement('span');badge.className='severity '+item.severity;badge.textContent=item.allowed?'ALLOWED':item.severity.toUpperCase();top.append(label,badge);const h=document.createElement('p');h.style.color='var(--text)';h.textContent=item.title;const sub=document.createElement('p');sub.textContent=item.detail;row.append(top,h,sub);output.appendChild(row);}
  };
  function showDefault(){output.replaceChildren();const empty=document.createElement('div');empty.className='result-empty';const strong=document.createElement('strong');strong.textContent='Ready to evaluate';const small=document.createElement('span');small.textContent='Edit the sample and select Run check.';empty.append(strong,small);output.appendChild(empty);state.textContent='READY';lastPlainText='';}
  function selectDemo(id, focus){
    if(!(id in samples))return;active=id;editor.value=samples[id];$('#demo-title').textContent=titles[id];$('#input-hint').textContent=hints[id];
    $$('.lab-tabs button').forEach(btn=>{const selected=btn.dataset.demo===id;btn.setAttribute('aria-selected',String(selected));btn.tabIndex=selected?0:-1;});
    $('#panel-demo').setAttribute('aria-labelledby','tab-'+id);
    if(focus)$('#tab-'+id).focus();
    showDefault();
  }
  $$('.lab-tabs button').forEach((btn,i)=>{
    btn.addEventListener('click',()=>selectDemo(btn.dataset.demo));
    btn.addEventListener('keydown',(event)=>{if(!['ArrowRight','ArrowLeft','Home','End'].includes(event.key))return;event.preventDefault();const tabs=$$('.lab-tabs button');let target=event.key==='Home'?0:event.key==='End'?tabs.length-1:(i+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;selectDemo(tabs[target].dataset.demo,true);});
  });
  $$('.filter').forEach(btn=>btn.addEventListener('click',()=>{$$('.filter').forEach(b=>{const selected=b===btn;b.classList.toggle('active',selected);b.setAttribute('aria-pressed',String(selected));});$$('.project-card').forEach(c=>{c.hidden=btn.dataset.filter!=='all'&&c.dataset.category!==btn.dataset.filter;});}));
  $$('[data-open-demo]').forEach(link=>link.addEventListener('click',()=>selectDemo(link.dataset.openDemo)));
  $('#reset-demo').addEventListener('click',()=>selectDemo(active));
  $('#run-demo').addEventListener('click',()=>{let findings;try{findings=active==='iac'?scanTerraform(editor.value):active==='agent'?agentPolicy(editor.value):cloudDetect(editor.value);}catch(error){findings=[{id:'INPUT',severity:'high',title:'Unable to analyze input',detail:error.message}];}render(findings);});
  $('#copy-result').addEventListener('click',async()=>{if(!lastPlainText)return;const b=$('#copy-result');try{await navigator.clipboard.writeText(lastPlainText);b.textContent='Copied ✓';setTimeout(()=>b.textContent='Copy results ↗',1600);}catch(_){b.textContent='Copy unavailable';setTimeout(()=>b.textContent='Copy results ↗',1600);}});
  const menu=$('#menu-toggle'),mobile=$('#mobile-nav');menu.addEventListener('click',()=>{const open=menu.getAttribute('aria-expanded')==='true';menu.setAttribute('aria-expanded',String(!open));mobile.hidden=open;});
  $$('.mobile-nav a').forEach(a=>a.addEventListener('click',()=>{mobile.hidden=true;menu.setAttribute('aria-expanded','false');}));
  const theme=$('#theme-toggle');const setTheme=(light)=>{document.body.classList.toggle('light',light);theme.setAttribute('aria-pressed',String(light));};
  theme.addEventListener('click',()=>setTheme(!document.body.classList.contains('light')));
  selectDemo('iac');
})();
