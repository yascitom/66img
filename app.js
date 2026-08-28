(function(){
  // ================= 基础引用 =================
  const $=id=>document.getElementById(id);
  const dz=$('dropzone'), fi=$('fileInput'), queue=$('queue');
  const webpToggle=$('webpToggle'), quality=$('quality'), qualityVal=$('qualityVal');
  const keepNameEl=$('keepName'), batchToggle=$('batchToggle'), batchBar=$('batchBar');
  const lockScreen=$('lockScreen'), lockbox=$('lockbox'), lockInput=$('lockInput'), lockBtn=$('lockBtn'), lockErr=$('lockErr');
  const mainApp=$('mainApp');
  const lightbox=$('lightbox'), lbMedia=$('lbMedia'), lbMeta=$('lbMeta');
  const HIST_KEY='yunwo_history', PWD_KEY='yunwo_pwd', MP_KEY='yunwo_multipart_tasks', TOKEN_KEY='yunwo_token';
  // 旧版（云汀云盘）本地数据一次性迁移：老用户的登录态、历史记录、分片续传进度不丢
  (function migrateLegacyKeys(){
    const pairs=[['oss_imgbed_history',HIST_KEY],['oss_imgbed_pwd',PWD_KEY],['yt_multipart_tasks',MP_KEY]];
    pairs.forEach(([oldK,newK])=>{
      const v=localStorage.getItem(oldK);
      if(v!==null && localStorage.getItem(newK)===null) localStorage.setItem(newK,v);
      if(v!==null) localStorage.removeItem(oldK);
    });
  })();
  // ================= 主题（白天 / 夜晚） =================
  // 首次访问按本机时间自动选择：7:00~18:59 用白天主题，其余时间用夜晚主题；
  // 手动切换后记住选择，之后不再自动判断
  const THEME_KEY='yunwo_theme';
  function applyTheme(t){
    document.documentElement.dataset.theme=t;
    document.querySelectorAll('.themebtn').forEach(b=>b.textContent=(t==='light'?'🌙':'☀️'));
    const m=$('themeColorMeta'); if(m) m.content=t==='light'?'#f2f4fa':'#0b0d12';
  }
  (function initTheme(){
    let t=localStorage.getItem(THEME_KEY);
    if(t!=='light'&&t!=='dark'){ const h=new Date().getHours(); t=(h>=7&&h<19)?'light':'dark'; }
    applyTheme(t);
  })();
  document.querySelectorAll('.themebtn').forEach(b=>b.addEventListener('click',()=>{
    const cur=document.documentElement.dataset.theme==='light'?'dark':'light';
    localStorage.setItem(THEME_KEY,cur); applyTheme(cur);
  }));
  const DEMO_PASSWORD='demo1234';
  // 超过该大小走分片上传（Multipart）；小文件走 PostObject 一次直传
  // 与服务端 PART_SIZE_MB 默认 10MB 对齐；分片即签即传，慢网络不限总时长、支持断点续传
  const MP_THRESHOLD=10*1024*1024;

  // 文件类型识别（与后端保持一致）
  const IMG_EXTS=['jpg','jpeg','png','gif','webp','svg','avif','bmp','ico','tiff'];
  const VIDEO_EXTS=['mp4','webm','mov','mkv','m4v','avi','flv','ts'];
  function fileTypeOf(name){
    const ext=(name.split('.').pop()||'').toLowerCase();
    if(IMG_EXTS.includes(ext)) return 'image';
    if(VIDEO_EXTS.includes(ext)) return 'video';
    return 'other';
  }
  function fileIcon(name){
    const ext=(name.split('.').pop()||'').toLowerCase();
    if(['zip','rar','7z','tar','gz','bz2','xz'].includes(ext)) return '📦';
    if(ext==='pdf') return '📕';
    if(['doc','docx','md','txt'].includes(ext)) return '📘';
    if(['xls','xlsx','csv'].includes(ext)) return '📗';
    if(['ppt','pptx'].includes(ext)) return '📙';
    if(['mp3','wav','flac','aac','ogg','m4a'].includes(ext)) return '🎵';
    if(['exe','apk','dmg','deb','msi'].includes(ext)) return '⚙️';
    return '📄';
  }

  let maxSizeMB=100;

  // ================= Toast =================
  function toast(msg, type){
    const box=$('toasts');
    const t=document.createElement('div');
    t.className='toast'+(type?' '+type:'');
    t.textContent=msg;
    box.appendChild(t);
    setTimeout(()=>{ t.classList.add('out'); setTimeout(()=>t.remove(),350); }, 2200);
  }

  // ================= 登录门禁（令牌制：明文密码只用于首次验证，之后本地只存 7 天令牌） =================
  function getToken(){
    try{
      const o=JSON.parse(localStorage.getItem(TOKEN_KEY)||'null');
      // 提前 60 秒视为过期，避免请求在途中过期
      if(o && o.t && o.e && o.e > Math.floor(Date.now()/1000)+60) return o.t;
    }catch(e){}
    return '';
  }
  function saveToken(t){
    try{
      const body=t.slice(0, t.lastIndexOf('.'));
      const p=JSON.parse(atob(body.replace(/-/g,'+').replace(/_/g,'/')));
      localStorage.setItem(TOKEN_KEY, JSON.stringify({t:t, e:p.e||0}));
    }catch(e){ /* 令牌格式异常则不保存 */ }
    localStorage.removeItem(PWD_KEY); // 拿到令牌后不再保存明文密码
  }
  function authFields(){ const t=getToken(); return t?{auth:t}:{}; }
  function authExpired(){
    localStorage.removeItem(TOKEN_KEY);
    lockInput.value=''; lockErr.textContent='登录已过期，请重新输入密码';
    lockScreen.classList.remove('hidden'); mainApp.classList.remove('unlocked');
  }

  // 身份预检：payload 为 {password}（登录）或 {auth}（令牌续期）
  async function checkAuth(payload){
    try{
      const r=await fetch('/api/sign',{
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify(Object.assign({check:true}, payload))
      });
      if(r.status===404) return {preview:true};
      const data=await r.json().catch(()=>({}));
      if(r.ok) return {ok:true, maxMB:data.maxMB, token:data.token};
      if(r.status===401) return {ok:false, expired:true, msg:data.error||'密码错误或会话已过期'};
      return {ok:false, msg:data.error||('服务端错误 '+r.status)};
    }catch(e){ return {preview:true}; }
  }

  function unlock(maxMB){
    if(maxMB){ maxSizeMB=maxMB; $('maxMBVal').textContent=maxMB; }
    lockScreen.classList.add('hidden');
    mainApp.classList.add('unlocked');
    loadCloud(false);
  }

  function showPreviewBanner(){
    const b=document.createElement('div');
    b.className='preview-banner';
    b.textContent='⚠️ 当前为静态预览模式：界面可完整体验，上传与云端文件需部署到 EO / ESA / CF 并配置环境变量后生效';
    mainApp.insertBefore(b, mainApp.children[1]);
  }

  async function tryUnlock(password, fromAuto){
    lockBtn.disabled=true;
    const r=await checkAuth({password:password});
    lockBtn.disabled=false;
    if(r.preview){
      if(password===DEMO_PASSWORD){ unlock(); showPreviewBanner(); }
      else if(!fromAuto){
        lockErr.textContent='预览演示模式，请输入演示密码：demo1234';
        lockbox.classList.remove('shake'); void lockbox.offsetWidth; lockbox.classList.add('shake');
      }
      return;
    }
    if(r.ok){
      if(r.token){
        saveToken(r.token);               // 保存 7 天令牌，明文密码即弃（7 天硬到期，不续期）
        lockErr.textContent=''; unlock(r.maxMB);
      }else{
        // 服务端未签发令牌 = 后端版本过旧，拒绝降级为本地保存明文密码
        lockErr.textContent='服务端未签发登录令牌，请将后端函数更新到最新版本';
        lockbox.classList.remove('shake'); void lockbox.offsetWidth; lockbox.classList.add('shake');
      }
    }
    else{
      if(fromAuto){ localStorage.removeItem(PWD_KEY); lockScreen.classList.remove('hidden'); lockErr.textContent=r.msg; }
      else{ lockErr.textContent=r.msg; lockbox.classList.remove('shake'); void lockbox.offsetWidth; lockbox.classList.add('shake'); }
    }
  }

  // 已存令牌的自动登录：令牌有效则直接解锁并换新，失效则清除回锁屏
  async function tryTokenLogin(token){
    const r=await checkAuth({auth:token});
    if(r.ok){ if(r.token) saveToken(r.token); unlock(r.maxMB); return; }
    if(r.preview){ unlock(); showPreviewBanner(); return; }
    localStorage.removeItem(TOKEN_KEY);
    lockErr.textContent=r.expired?'登录已过期，请重新输入密码':r.msg;
    lockScreen.classList.remove('hidden');
  }

  lockBtn.addEventListener('click',()=>tryUnlock(lockInput.value,false));
  lockInput.addEventListener('keydown',e=>{ if(e.key==='Enter') tryUnlock(lockInput.value,false); });
  $('logoutBtn').addEventListener('click',()=>{
    localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(PWD_KEY);
    lockInput.value=''; lockErr.textContent='';
    lockScreen.classList.remove('hidden'); mainApp.classList.remove('unlocked');
  });
  // 自动登录：优先用已存令牌；旧版明文密码自动验证一次并迁移为令牌
  if(getToken()) tryTokenLogin(getToken());
  else tryUnlock(localStorage.getItem(PWD_KEY)||'', true);

  quality.addEventListener('input',()=>qualityVal.textContent=quality.value);

  // ================= 保留原文件名（默认开启，记住选择） =================
  // 开启后文件以清洗后的原名存储（中文与字母数字 ._- 保留，其他字符替换为 -，最长 80 字符）；
  // 关闭则使用随机名。同名文件已存在时 OSS 会拒绝覆盖，上传会失败提示。
  const KEEPNAME_KEY='yunwo_keepname';
  keepNameEl.checked=localStorage.getItem(KEEPNAME_KEY)!=='0'; // 默认保留
  keepNameEl.addEventListener('change',()=>localStorage.setItem(KEEPNAME_KEY, keepNameEl.checked?'1':'0'));

  // ================= 多格式复制（URL / Markdown / HTML / BBCode，记住选择） =================
  const FMT_KEY='yunwo_copyfmt';
  const FMT_LABEL={url:'链接',md:'Markdown',html:'HTML 代码',bbcode:'BBCode'};
  if(!FMT_LABEL[localStorage.getItem(FMT_KEY)]) localStorage.setItem(FMT_KEY,'url');
  let curFmt=localStorage.getItem(FMT_KEY);
  // 灯箱里的格式按钮：点击即选中该格式并完成复制
  const lbFmtRow=$('lbFmtRow');
  function syncFmtBtns(){ [...lbFmtRow.children].forEach(b=>b.classList.toggle('active', b.dataset.fmt===curFmt)); }
  syncFmtBtns();
  // 按当前格式生成引用文本：图片给嵌入标签，其他类型给普通链接
  function formatLink(f){
    const fmt=curFmt||'url';
    const name=f.key.split('/').pop();
    const t=f.type||fileTypeOf(f.key);
    if(fmt==='md') return t==='image'?('![img]('+f.url+')'):('['+name+']('+f.url+')');
    if(fmt==='html'){
      if(t==='image') return '<img src="'+f.url+'" alt="'+name+'">';
      if(t==='video') return '<video src="'+f.url+'" controls></video>';
      return '<a href="'+f.url+'">'+name+'</a>';
    }
    if(fmt==='bbcode') return t==='image'?('[img]'+f.url+'[/img]'):('[url='+f.url+']'+name+'[/url]');
    return f.url;
  }
  function copyText(text,label){
    navigator.clipboard.writeText(text).then(
      ()=>toast((label||'链接')+'已复制','ok'),
      ()=>toast('复制失败，请检查浏览器剪贴板权限','err'));
  }

  // ================= 上传（批量队列） =================
  dz.addEventListener('click',()=>fi.click());
  fi.addEventListener('change',()=>{ handleFiles([...fi.files]); fi.value=''; });
  ['dragover','dragenter'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.add('dragover');}));
  ['dragleave','drop'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.remove('dragover');}));
  dz.addEventListener('drop',ev=>handleFiles([...ev.dataTransfer.files]));
  window.addEventListener('paste',ev=>{
    const files=[...(ev.clipboardData||[]).items].filter(i=>i.type.startsWith('image/')).map(i=>i.getAsFile());
    if(files.length) handleFiles(files);
  });

  let uploading=false;
  const pending=[];

  // ================= 上传管理器（右下角浮动面板） =================
  // 队列不再占用上传卡片内的位置：进度收进右下浮层，大文件长传时可继续浏览/管理云端文件。
  // 面板头部实时汇总进度，全部完成后露出「清空」入口；点击头部可折叠。
  const upPanel=$('upPanel'), upStatus=$('upStatus'), upDot=$('upDot'), upClear=$('upClear');
  function pausedErr(){ const e=new Error('已暂停'); e.code='PAUSED'; return e; }
  function cancelledErr(){ const e=new Error('已取消'); e.code='CANCELLED'; return e; }

  // 每个队列项右侧的控制按钮：上传中→暂停/取消，已暂停→继续/取消，排队中→取消，结束态→无
  function setQControls(item, state){
    const act=item.el.querySelector('.qact');
    act.innerHTML='';
    const mk=(txt,primary,fn)=>{
      const b=document.createElement('button');
      b.className='qbtn'+(primary?' primary':'');
      b.textContent=txt;
      b.addEventListener('click',()=>fn());
      act.appendChild(b);
    };
    if(state==='uploading'){ mk('暂停',0,()=>pauseItem(item)); mk('取消',0,()=>cancelItem(item)); }
    else if(state==='paused'){ mk('继续',1,()=>resumeItem(item)); mk('取消',0,()=>cancelItem(item)); }
    else if(state==='queued'){ mk('取消',0,()=>cancelItem(item)); }
    // done / err：不留按钮（复制链接在云端列表与灯箱里都有入口）
  }

  // 暂停：打标记 + 中断当前 XHR，上传循环在分片边界/进度回调里检测标记抛出 PAUSED。
  // 已传分片进度保留在 localStorage，「继续」时从断点接着传（小文件则整体重传）。
  function pauseItem(item){
    if(item.state!=='uploading') return;
    item.paused=true;
    if(item.currentXhr){ try{item.currentXhr.abort();}catch(e){} }
    setQ(item, item.lastPct||0, '正在暂停…');
  }
  function resumeItem(item){
    if(item.state!=='paused') return;
    item.paused=false; item.state='queued';
    item.el.classList.remove('paused');
    setQ(item, item.lastPct||8, '排队等待继续上传…');
    setQControls(item,'queued');
    pending.unshift(item);
    updateUpHead();
    processQueue();
  }
  // 取消：排队中直接移除；上传中先断 XHR 再交给 processQueue 收尾；
  // 已初始化过分片的还要通知 OSS 清理残留分片、删掉本机续传进度
  async function cancelItem(item){
    if(item.state==='done'||item.state==='err'){ item.el.remove(); updateUpHead(); return; }
    item.cancelled=true;
    const i=pending.indexOf(item); if(i>=0) pending.splice(i,1);
    if(item.currentXhr){ try{item.currentXhr.abort();}catch(e){} }
    const fp=fpOf(item.file), task=getMpTasks()[fp];
    if(task && task.uploadId){
      try{ await mpApi({action:'abort', key:task.key, uploadId:task.uploadId, session:task.session||''}); }catch(e){}
      delMpTask(fp);
    }
    if(item.state!=='uploading'){ item.el.remove(); updateUpHead(); }
  }

  function updateUpHead(){
    const items=queue.children;
    if(!items.length){ upPanel.classList.remove('show'); return; }
    let done=0, fail=0, pausedN=0;
    for(const el of items){
      const st=el.querySelector('.st');
      if(st.classList.contains('ok')) done++;
      else if(st.classList.contains('err')) fail++;
      if(el.classList.contains('paused')) pausedN++;
    }
    upPanel.classList.add('show');
    if(uploading){
      upStatus.textContent='上传中 '+(done+fail)+'/'+items.length+(pausedN?' · 暂停 '+pausedN:'');
      upDot.className='up-dot active';
      upClear.style.display='none';
    }else{
      if(!fail && !pausedN && done===items.length){
        upStatus.textContent='已完成 '+items.length+' 个文件';
        upDot.className='up-dot ok';
      }else{
        const parts=[];
        if(done) parts.push('完成 '+done+' 个');
        if(fail) parts.push('失败 '+fail+' 个');
        if(pausedN) parts.push('暂停 '+pausedN+' 个');
        upStatus.textContent=parts.join(' · ')||('共 '+items.length+' 个');
        upDot.className='up-dot '+(fail?'err':'warn');
      }
      upClear.style.display='';
    }
  }
  $('upHead').addEventListener('click',e=>{
    if(e.target.closest('#upClear')) return; // 清空不触发折叠
    upPanel.classList.toggle('folded');
  });
  upClear.addEventListener('click',()=>{
    queue.innerHTML='';
    upPanel.classList.remove('show','folded');
  });

  function fmtSize(bytes){
    if(bytes>=1048576) return (bytes/1048576).toFixed(1)+' MB';
    return (bytes/1024).toFixed(0)+' KB';
  }

  function handleFiles(files){
    if(!files.length) return;
    const maxBytes=maxSizeMB*1024*1024;
    const overs=files.filter(f=>f.size>maxBytes);
    overs.forEach(f=>toast(f.name+' 超过 '+maxSizeMB+'MB，已跳过','err'));
    const ok=files.filter(f=>f.size<=maxBytes);
    if(!ok.length) return;
    ok.forEach(f=>{
      const item={file:f, el:buildQItem(f), state:'queued', lastPct:0};
      pending.push(item);
      queue.appendChild(item.el); // 入列即上墙：面板立即出现，不用等轮到它上传
      setQControls(item,'queued');
    });
    updateUpHead();
    if(!uploading) processQueue();
  }

  function buildQItem(file){
    const el=document.createElement('div');
    el.className='qitem';
    const thumb=file.type.startsWith('image/')
      ? '<img src="'+URL.createObjectURL(file)+'">'
      : '<div class="qico">'+(fileTypeOf(file.name)==='video'?'🎬':fileIcon(file.name))+'</div>';
    el.innerHTML=
      thumb+
      '<div class="info"><div class="name">'+escapeHtml(file.name)+'</div>'+
      '<div class="st">排队中 · '+fmtSize(file.size)+'</div>'+
      '<div class="qbar"><i></i></div></div>'+
      '<div class="qact"></div>';
    return el;
  }

  function escapeHtml(s){ return s.replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

  function setQ(item, pct, text, cls){
    const st=item.el.querySelector('.st'), bar=item.el.querySelector('.qbar>i');
    st.textContent=text; st.className='st'+(cls?' '+cls:'');
    bar.style.width=pct+'%';
  }

  // 图片压缩（默认关闭，原图直传；GIF / SVG 任何时候都不压缩，保留动图与矢量特性）
  function maybeCompress(file){
    return new Promise(resolve=>{
      if(!webpToggle.checked || !file.type.startsWith('image/') || file.type==='image/gif' || file.type==='image/svg+xml') return resolve(file);
      const img=new Image();
      img.onload=()=>{
        const c=document.createElement('canvas');
        c.width=img.naturalWidth; c.height=img.naturalHeight;
        c.getContext('2d').drawImage(img,0,0);
        c.toBlob(b=>{
          if(b && b.size<file.size) resolve(new File([b], file.name.replace(/\.\w+$/,'')+'.webp', {type:'image/webp'}));
          else resolve(file);
        },'image/webp', quality.value/100);
      };
      img.onerror=()=>resolve(file);
      img.src=URL.createObjectURL(file);
    });
  }

  // ================= 同名冲突弹窗 =================
  // 返回新文件名；点「取消」/遮罩/Esc 返回 null
  const nameModal=$('nameModal'), nmInput=$('nmInput'), nmName=$('nmName');
  function randCode6(){
    const chars='abcdefghijklmnopqrstuvwxyz0123456789';
    const buf=new Uint8Array(6); crypto.getRandomValues(buf);
    return [...buf].map(b=>chars[b%36]).join('');
  }
  function addConflictSuffix(name){
    const i=name.lastIndexOf('.');
    const code=randCode6();
    return i>0 ? name.slice(0,i)+'-'+code+name.slice(i) : name+'-'+code;
  }
  function askConflictName(name){
    return new Promise(resolve=>{
      nmName.textContent=name;
      nmInput.value=name;
      nameModal.classList.add('show');
      setTimeout(()=>{ nmInput.focus(); nmInput.select(); },50);
      const done=v=>{
        nameModal.classList.remove('show');
        window.removeEventListener('keydown',onKey,true);
        resolve(v);
      };
      const onKey=e=>{
        if(e.key==='Escape'){ e.stopPropagation(); done(null); }
        if(e.key==='Enter'&&document.activeElement===nmInput){ e.stopPropagation(); $('nmRename').click(); }
      };
      window.addEventListener('keydown',onKey,true);
      $('nmRename').onclick=()=>{
        const v=nmInput.value.trim();
        if(!v){ toast('文件名不能为空','err'); return; }
        done(v);
      };
      $('nmAuto').onclick=()=>done(addConflictSuffix(nmInput.value.trim()||name));
      $('nmCancel').onclick=()=>done(null);
      nameModal.onclick=e=>{ if(e.target===nameModal) done(null); };
    });
  }

  async function processQueue(){
    if(uploading) return;
    uploading=true;
    updateUpHead();
    while(pending.length){
      const item=pending.shift();
      if(item.state==='cancelled'){ item.el.remove(); updateUpHead(); continue; }
      item.state='uploading';
      setQControls(item,'uploading');
      try{
        setQ(item, item.lastPct||8, fileTypeOf(item.file.name)==='image'?'压缩处理中…':'准备上传…');
        let file=await maybeCompress(item.file);

        // 同名冲突：弹窗让用户重命名，或自动加 6 位编码后缀重试
        let result;
        for(;;){
          if(item.paused) throw pausedErr();
          if(item.cancelled) throw cancelledErr();
          try{
            if(file.size>MP_THRESHOLD){
              result=await uploadMultipart(item, file); // 大文件：分片直传（断点续传）
            }else{
              result=await uploadSimple(item, file);    // 小文件：PostObject 表单直传
            }
            break;
          }catch(e){
            if(e.code!=='CONFLICT') throw e;
            setQ(item, 100, '同名文件已存在，等待处理…', 'err');
            const newName=await askConflictName(file.name);
            if(newName===null) throw new Error('已取消（同名文件冲突）');
            file=new File([file], newName, {type:file.type});
            setQ(item, 8, '以新名称重新上传…');
          }
        }

        item.state='done'; setQControls(item,'done');
        setQ(item, 100, '✓ 完成 · '+fmtSize(file.size)+' → '+result.dir, 'ok');
        addHistory(result.url);
        prependCloudItem({key:result.key, time:new Date().toISOString(), size:file.size, url:result.url, type:fileTypeOf(result.key)});
        toast(file.name+' 上传成功','ok');
        updateUpHead();
      }catch(e){
        if(e.code==='PAUSED'){
          item.state='paused'; item.el.classList.add('paused');
          setQ(item, item.lastPct||0, '⏸ 已暂停 · 点「继续」接着传');
          setQControls(item,'paused');
          updateUpHead();
          continue;
        }
        if(e.code==='CANCELLED'){ item.el.remove(); updateUpHead(); continue; }
        item.state='err'; setQControls(item,'err');
        setQ(item, 100, '✗ '+(e.message||'上传失败'), 'err');
        toast('上传失败：'+e.message,'err');
        updateUpHead();
      }
    }
    uploading=false;
    updateUpHead();
  }

  // ================= 上传速度表 =================
  // 进度回调工厂：bytesNow=该文件已传总字节（分片模式含此前已完成的分片），
  // 0.4s 采样窗口 + EMA 平滑防数字跳动，300ms 节流刷新状态文本，textFn 生成状态前缀。
  function fmtSpeed(bps){
    if(bps>=1048576) return (bps/1048576).toFixed(1)+' MB/s';
    if(bps>=1024) return Math.round(bps/1024)+' KB/s';
    return Math.max(1,Math.round(bps))+' B/s';
  }
  function makeProgress(item, file, textFn){
    let lastT=0, lastB=null, speed=0, lastPaint=0;
    return bytesNow=>{
      const now=Date.now();
      if(lastB===null){ lastB=bytesNow; lastT=now; }
      const dt=(now-lastT)/1000;
      if(dt>=0.4){
        const inst=(bytesNow-lastB)/dt;
        speed=speed? speed*0.6+inst*0.4 : inst;
        lastT=now; lastB=bytesNow;
      }
      if(now-lastPaint>=300){
        lastPaint=now;
        const pct=bytesNow/file.size*100;
        item.lastPct=Math.min(96, 2+pct*0.94);
        setQ(item, item.lastPct, textFn(pct)+(speed>1024?' · '+fmtSpeed(speed):''));
      }
    };
  }

  // ================= 小文件：PostObject 一次直传 =================
  async function getSign(file){
    const sr=await fetch('/api/sign',{
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify(Object.assign({filename:file.name, size:file.size, keepName:keepNameEl.checked}, authFields()))
    });
    if(sr.status===404) throw new Error('预览模式无后端');
    const sign=await sr.json().catch(()=>({}));
    if(sr.status===401){ authExpired(); throw new Error('登录已过期，请重新输入密码'); }
    if(!sr.ok) throw new Error(sign.error||('签名失败 '+sr.status));
    return sign;
  }
  // XHR 表单直传（fetch 拿不到上传进度；XHR 的 upload.onprogress 才能算实时速度）
  function postToOSS(sign, file, item, onProgress){
    const fd=new FormData();
    Object.entries(sign.fields).forEach(([k,v])=>fd.append(k,v));
    fd.append('file',file,file.name);
    return new Promise((resolve,reject)=>{
      const x=new XMLHttpRequest();
      item.currentXhr=x;
      x.open('POST', sign.host);
      x.upload.onprogress=e=>{ if(e.lengthComputable && onProgress) onProgress(e.loaded); };
      x.onload=()=>{
        item.currentXhr=null;
        resolve({ok:x.status>=200&&x.status<300, status:x.status, text:async()=>x.responseText||''});
      };
      x.onerror=()=>{
        item.currentXhr=null;
        if(item.paused){ reject(pausedErr()); return; }
        if(item.cancelled){ reject(cancelledErr()); return; }
        reject(new Error('网络中断（若反复出现，请检查桶 CORS 的来源是否包含本站域名）'));
      };
      x.onabort=()=>{
        item.currentXhr=null;
        reject(item.cancelled?cancelledErr():pausedErr());
      };
      x.send(fd);
    });
  }
  async function uploadSimple(item, file){
    if(item.paused) throw pausedErr();
    if(item.cancelled) throw cancelledErr();
    setQ(item, 5, '获取签名…');
    let sign=await getSign(file);
    const progress=makeProgress(item, file, pct=>'上传到 OSS · '+Math.round(pct)+'%');
    let ur=await postToOSS(sign, file, item, progress);
    if(!ur.ok){
      const t=await ur.text().catch(()=> '');
      // 同名冲突：x-oss-forbid-overwrite 拒绝，抛 CONFLICT 交给上层弹窗处理
      if(ur.status===409||/FileAlreadyExists/i.test(t)){ const err=new Error('同名文件已存在'); err.code='CONFLICT'; throw err; }
      // 慢网络可能拖过 Policy 10 分钟有效期：检测到过期就自动重签重传一次
      if(/Policy expired|AccessDenied/i.test(t)){
        setQ(item, 5, '签名已过期，自动重签重传…');
        sign=await getSign(file);
        ur=await postToOSS(sign, file, item, progress);
        if(ur.status===409){ const err=new Error('同名文件已存在'); err.code='CONFLICT'; throw err; }
      }
    }
    if(!ur.ok) throw new Error('OSS 返回 '+ur.status);
    return {url:sign.url, dir:sign.dir, key:sign.fields.key};
  }

  // ================= 大文件：分片上传（Multipart） =================
  // 断点续传：进度保存在 localStorage，中断后重新选择同一文件自动续传；
  // 每个分片「即签即传」（预签名 URL 1 小时有效，失败自动重签），总时长不设限。
  function getMpTasks(){ try{return JSON.parse(localStorage.getItem(MP_KEY))||{}}catch(e){return{}} }
  function saveMpTask(fp, task){ const all=getMpTasks(); all[fp]=task; localStorage.setItem(MP_KEY, JSON.stringify(all)); }
  function delMpTask(fp){ const all=getMpTasks(); delete all[fp]; localStorage.setItem(MP_KEY, JSON.stringify(all)); }
  function fpOf(file){ return file.name+'_'+file.size; }

  async function mpApi(payload){
    const r=await fetch('/api/multipart',{
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify(Object.assign({}, payload, authFields()))
    });
    if(r.status===404) throw new Error('预览模式无后端');
    const data=await r.json().catch(()=>({}));
    if(r.status===401){ authExpired(); throw new Error('登录已过期，请重新输入密码'); }
    if(!r.ok){
      const err=new Error(data.error||('分片服务错误 '+r.status));
      if(data.code) err.code=data.code; // 如 BAD_SESSION：会话令牌失效，交给外层整体重启
      throw err;
    }
    return data;
  }

  // 精简 MD5（ArrayBuffer → hex，基于 Paul Johnston 公共域实现改写）
  // 用途：本地计算分片内容 MD5 作为 ETag 兜底 —— OSS UploadPart 的 ETag 即分片内容 MD5，
  // 这样即使桶 CORS 没配 ExposeHeader: ETag（或被其他通配规则抢先匹配），上传也不受影响。
  function md5Hex(buffer){
    const bytes=new Uint8Array(buffer);
    const n=bytes.length;
    const bitLen=n*8;
    const padLen=((n%64)<56?56:120)-(n%64);
    const total=n+padLen+8;
    const buf=new Uint8Array(total);
    buf.set(bytes); buf[n]=0x80;
    const dv=new DataView(buf.buffer);
    dv.setUint32(total-8, bitLen>>>0, true);
    dv.setUint32(total-4, Math.floor(bitLen/4294967296), true);
    const S=[7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
             5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
             4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
             6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
    const K=new Uint32Array(64);
    for(let i=0;i<64;i++) K[i]=Math.floor(Math.abs(Math.sin(i+1))*4294967296);
    let a0=0x67452301, b0=0xefcdab89, c0=0x98badcfe, d0=0x10325476;
    const M=new Uint32Array(16);
    for(let off=0; off<total; off+=64){
      for(let i=0;i<16;i++) M[i]=dv.getUint32(off+i*4, true);
      let A=a0, B=b0, C=c0, D=d0;
      for(let i=0;i<64;i++){
        let F, g;
        if(i<16){ F=(B&C)|(~B&D); g=i; }
        else if(i<32){ F=(D&B)|(~D&C); g=(5*i+1)%16; }
        else if(i<48){ F=B^C^D; g=(3*i+5)%16; }
        else { F=C^(B|~D); g=(7*i)%16; }
        const tmp=D;
        const sum=(A+F+K[i]+M[g]);
        D=C; C=B;
        const s=S[i];
        B=(B+(((sum<<s)|(sum>>>(32-s)))))|0;
        A=tmp;
      }
      a0=(a0+A)|0; b0=(b0+B)|0; c0=(c0+C)|0; d0=(d0+D)|0;
    }
    const out=new Uint8Array(16);
    const ov=new DataView(out.buffer);
    ov.setUint32(0, a0, true); ov.setUint32(4, b0, true);
    ov.setUint32(8, c0, true); ov.setUint32(12, d0, true);
    let hex='';
    for(let i=0;i<16;i++) hex+=out[i].toString(16).padStart(2,'0');
    return hex;
  }

  // XHR PUT 单个分片（fetch 拿不到上传进度，XHR 可以）
  // md5Fallback：本地算好的分片 MD5，读不到 ETag 响应头时兜底
  function xhrPut(url, blob, mime, md5Fallback, onProgress, item){
    return new Promise((resolve,reject)=>{
      const x=new XMLHttpRequest();
      if(item) item.currentXhr=x;
      x.open('PUT', url);
      x.setRequestHeader('Content-Type', mime); // 须与服务端签名时的 Content-Type 完全一致
      x.upload.onprogress=e=>{ if(e.lengthComputable) onProgress(e.loaded); };
      const clear=()=>{ if(item && item.currentXhr===x) item.currentXhr=null; };
      x.onload=()=>{
        clear();
        if(x.status>=200 && x.status<300){
          const etag=x.getResponseHeader('ETag');
          // 优先用服务端返回的 ETag；CORS 未暴露时用本地 MD5（二者本来相等）
          resolve((etag || md5Fallback || '').replace(/"/g,''));
        }else{
          const m=(x.responseText||'').match(/<Code>([^<]+)<\/Code>/);
          const err=new Error('分片上传失败：'+(m?m[1]:('HTTP '+x.status)));
          if(/NoSuchUpload/.test(x.responseText||'')) err.code='NoSuchUpload';
          reject(err);
        }
      };
      x.onerror=()=>{
        clear();
        if(item && item.paused){ reject(pausedErr()); return; }
        if(item && item.cancelled){ reject(cancelledErr()); return; }
        reject(new Error('网络中断（若反复出现，请检查桶 CORS 的来源是否包含本站域名、方法是否允许 PUT）'));
      };
      x.onabort=()=>{
        clear();
        reject(item && item.cancelled ? cancelledErr() : pausedErr());
      };
      x.send(blob);
    });
  }

  // 单个分片：最多 3 次尝试，每次都重新签名（慢网络下签名过期也能自愈）
  async function uploadPartWithRetry(task, n, chunk, onProgress, item){
    const md5=md5Hex(await chunk.arrayBuffer()); // 只算一次，重试复用
    let lastErr=null;
    for(let attempt=1; attempt<=3; attempt++){
      if(item.paused) throw pausedErr();
      if(item.cancelled) throw cancelledErr();
      try{
        const sign=await mpApi({action:'part', key:task.key, uploadId:task.uploadId, partNumber:n, mime:task.mime, session:task.session||''});
        const etag=await xhrPut(sign.url, chunk, task.mime, md5, onProgress, item);
        if(!etag) throw new Error('ETag 为空');
        return etag;
      }catch(e){
        if(item.paused) throw pausedErr();
        if(item.cancelled) throw cancelledErr();
        lastErr=e;
        if(e.code==='NoSuchUpload'||e.code==='BAD_SESSION') throw e; // 会话已失效：不重试，交给外层整体重启
        if(attempt<3) await new Promise(r=>setTimeout(r, 1500*attempt));
      }
    }
    throw lastErr;
  }

  async function uploadMultipart(item, file){
    const fp=fpOf(file);
    for(let restarted=0; restarted<2; restarted++){
      if(item.paused) throw pausedErr();
      if(item.cancelled) throw cancelledErr();
      const saved=getMpTasks()[fp];
      const resumed=!!(saved && saved.uploadId && saved.key);
      let task;
      try{
        if(!resumed){
          setQ(item, 10, '初始化分片上传…');
          const init=await mpApi({action:'init', filename:file.name, size:file.size, mime:file.type||'application/octet-stream', keepName:keepNameEl.checked});
          task={key:init.key, uploadId:init.uploadId, partSize:init.partSize, session:init.session||'', dir:init.dir, mime:file.type||'application/octet-stream', parts:{}};
          saveMpTask(fp, task);
        }else{
          task=saved;
          toast('检测到该文件有未完成的上传，自动断点续传','ok');
        }

        const total=Math.ceil(file.size/task.partSize);
        const partBytes=n=>Math.min(task.partSize, file.size-(n-1)*task.partSize);
        let doneBytes=Object.keys(task.parts).reduce((s,k)=>s+partBytes(+k),0);
        let curPart=1;
        const progress=makeProgress(item, file, pct=>'分片 '+curPart+'/'+total+' 上传中 · '+Math.round(pct)+'%');

        for(let n=1; n<=total; n++){
          if(task.parts[n]) continue; // 已成功上传的分片直接跳过（断点续传核心）
          if(item.paused) throw pausedErr();
          if(item.cancelled) throw cancelledErr();
          curPart=n;
          const start=(n-1)*task.partSize;
          const chunk=file.slice(start, start+partBytes(n));
          const etag=await uploadPartWithRetry(task, n, chunk, loaded=>{
            if(item.paused||item.cancelled){ if(item.currentXhr) item.currentXhr.abort(); return; }
            progress(doneBytes+loaded);
          }, item);
          task.parts[n]=etag; saveMpTask(fp, task);
          doneBytes+=partBytes(n);
          item.lastPct=2+(doneBytes/file.size)*94;
          setQ(item, item.lastPct, '分片 '+n+'/'+total+' 完成 · '+Math.round(doneBytes/file.size*100)+'%');
        }

        setQ(item, 97, '合并分片…');
        const parts=Object.keys(task.parts).map(k=>({partNumber:+k, etag:task.parts[k]})).sort((a,b)=>a.partNumber-b.partNumber);
        const done=await mpApi({action:'complete', key:task.key, uploadId:task.uploadId, session:task.session||'', parts});
        delMpTask(fp);
        return {url:done.url, dir:done.dir, key:done.key};
      }catch(e){
        if(e.code==='PAUSED'||e.code==='CANCELLED') throw e; // 暂停/取消：不重试不重启，交给外层收尾
        if((e.code==='NoSuchUpload'||e.code==='BAD_SESSION') && restarted===0){
          // OSS 侧会话或本地令牌已失效（如超时 7 天被清理）：清掉本地进度，自动重来一次
          delMpTask(fp);
          setQ(item, 10, '续传会话已过期，自动重新开始…');
          continue;
        }
        throw e; // 进度保留在 localStorage，下次重选同一文件可续传
      }
    }
  }

  // ================= 云端文件 =================
  let cloudToken='';
  let cloudItems=[];
  let curDir='all';
  let batchMode=false;        // 批量管理模式开关
  const selected=new Set();   // 已勾选文件的 key 集合
  let dragKeys=null;          // 正在拖拽移动的文件 key 列表
  const TYPE_DIR={image:'img',video:'video',other:'other'};

  // 视图切换：平铺 grid / 瀑布流 fall / 列表 list（记住用户选择）
  const VIEW_KEY='yunwo_view';
  let curView=localStorage.getItem(VIEW_KEY)||'grid';
  if(!['grid','fall','list'].includes(curView)) curView='grid';
  function applyView(){
    $('cloudList').dataset.view=curView;
    [...$('viewSwitch').children].forEach(b=>b.classList.toggle('active',b.dataset.view===curView));
  }
  $('viewSwitch').addEventListener('click',e=>{
    const btn=e.target.closest('.viewbtn');
    if(!btn || btn.dataset.view===curView) return;
    curView=btn.dataset.view; localStorage.setItem(VIEW_KEY,curView);
    applyView(); renderCloud($('cloudSearch').value);
  });

  // 排序方式（记住用户选择；对全部 / 图片 / 视频 / 其他 所有标签页生效）
  const SORT_KEY='yunwo_sort';
  let curSort=localStorage.getItem(SORT_KEY)||'time_desc';
  function sortItems(items){
    const arr=[...items];
    if(curSort==='time_asc') arr.sort((a,b)=>new Date(a.time||0)-new Date(b.time||0));
    else if(curSort==='size_desc') arr.sort((a,b)=>(b.size||0)-(a.size||0));
    else if(curSort==='size_asc') arr.sort((a,b)=>(a.size||0)-(b.size||0));
    else arr.sort((a,b)=>new Date(b.time||0)-new Date(a.time||0)); // time_desc 默认：最新在前
    return arr;
  }

  // 目录标签页切换
  $('dirTabs').addEventListener('click',e=>{
    const tab=e.target.closest('.tab');
    if(!tab || tab.dataset.dir===curDir) return;
    curDir=tab.dataset.dir;
    [...$('dirTabs').children].forEach(t=>t.classList.toggle('active',t===tab));
    loadCloud(false);
  });

  function gridTile(f){
    const t=f.type||fileTypeOf(f.key);
    const u=escapeHtml(f.url); // 属性上下文必须转义，防 key 中特殊字符造成属性注入
    if(t==='image') return '<img loading="lazy" src="'+u+'" alt="">';
    if(t==='video') return '<video muted preload="metadata" src="'+u+'"></video><div class="badge">🎬 视频</div>';
    return '<div class="ftile"><div class="fico">'+fileIcon(f.key)+'</div><div class="fext">'+escapeHtml((f.key.split('.').pop()||'file').slice(0,6))+'</div></div>';
  }

  function renderCloud(filter){
    const list=$('cloudList');
    list.innerHTML='';
    const kw=(filter||'').toLowerCase();
    const base=kw? cloudItems.filter(f=>f.key.toLowerCase().includes(kw)) : cloudItems;
    const items=sortItems(base);
    $('cloudCount').textContent=kw? `（筛选出 ${items.length} / 共 ${cloudItems.length}）` : (cloudItems.length?`（${cloudItems.length}）`:'');
    if(!items.length){
      list.innerHTML='<div class="empty" style="grid-column:1/-1">'+(kw?'没有匹配的文件':'这个目录还是空的，传一个试试 ↑')+'</div>';
      return;
    }
    items.forEach((f,i)=>{
      const d=document.createElement('div');
      d.className='gitem'; d.style.animationDelay=(Math.min(i,12)*0.03)+'s';
      const nm=f.key.split('/').pop();
      const sub=(f.size?fmtSize(f.size):'')+(f.size&&f.time?' · ':'')+(f.time?new Date(f.time).toLocaleDateString():'');
      d.innerHTML=gridTile(f)+'<div class="selbox">✓</div>'
        +'<div class="ginfo"><div class="gname">'+escapeHtml(nm)+'</div><div class="gsub">'+escapeHtml(sub)+'</div></div>'
        +'<div class="lmeta"><span class="lname">'+escapeHtml(nm)+'</span>'
        +'<span class="linfo">'+(f.size?fmtSize(f.size):'')+(f.size&&f.time?' · ':'')+(f.time?new Date(f.time).toLocaleString():'')+'</span></div>';
      if(selected.has(f.key)) d.classList.add('sel');
      d.addEventListener('click',()=>{
        if(batchMode){
          if(selected.has(f.key)){ selected.delete(f.key); d.classList.remove('sel'); }
          else{ selected.add(f.key); d.classList.add('sel'); }
          updateBatchBar();
          return;
        }
        openLightbox(f);
      });
      // 拖拽移动：拖到上方目录标签即移动到对应目录（批量模式下拖动已选中的文件会带走整组）
      d.draggable=true;
      d.addEventListener('dragstart',e=>{
        dragKeys=(batchMode&&selected.has(f.key))? [...selected] : [f.key];
        e.dataTransfer.setData('text/plain', f.key);
        e.dataTransfer.effectAllowed='move';
        d.classList.add('dragging');
      });
      d.addEventListener('dragend',()=>{
        d.classList.remove('dragging'); dragKeys=null;
        [...$('dirTabs').children].forEach(t=>t.classList.remove('dropover'));
      });
      list.appendChild(d);
    });
  }

  // ================= 批量操作（多选 / 批量复制 / 批量删除） =================
  function updateBatchBar(){
    $('batchCount').textContent='已选 '+selected.size+' 项';
  }
  function setBatch(on){
    batchMode=on;
    $('cloudList').classList.toggle('batch',on);
    batchToggle.classList.toggle('active',on);
    batchBar.classList.toggle('show',on);
    if(!on) selected.clear();
    updateBatchBar();
    renderCloud($('cloudSearch').value);
  }
  batchToggle.addEventListener('click',()=>setBatch(!batchMode));
  $('batchCancel').addEventListener('click',()=>setBatch(false));
  $('batchAll').addEventListener('click',()=>{
    const kw=($('cloudSearch').value||'').toLowerCase();
    cloudItems.forEach(f=>{ if(!kw || f.key.toLowerCase().includes(kw)) selected.add(f.key); });
    updateBatchBar(); renderCloud($('cloudSearch').value);
  });
  // 反选：当前筛选范围内，已选的取消、未选的选中
  $('batchInvert').addEventListener('click',()=>{
    const kw=($('cloudSearch').value||'').toLowerCase();
    cloudItems.forEach(f=>{
      if(kw && !f.key.toLowerCase().includes(kw)) return;
      if(selected.has(f.key)) selected.delete(f.key); else selected.add(f.key);
    });
    updateBatchBar(); renderCloud($('cloudSearch').value);
  });
  $('batchCopy').addEventListener('click',()=>{
    if(!selected.size){ toast('请先勾选文件'); return; }
    const kw=($('cloudSearch').value||'').toLowerCase();
    const items=sortItems(cloudItems.filter(f=>selected.has(f.key)&&(!kw||f.key.toLowerCase().includes(kw))));
    copyText(items.map(formatLink).join('\n'), items.length+' 条'+FMT_LABEL[curFmt]);
  });
  $('batchDelete').addEventListener('click',async ()=>{
    const btn=$('batchDelete');
    if(!selected.size){ toast('请先勾选文件'); return; }
    if(!btn.dataset.armed){
      btn.dataset.armed='1'; btn.textContent='再点一次确认删除 '+selected.size+' 个';
      setTimeout(()=>{ btn.dataset.armed=''; btn.textContent='删除'; },3000);
      return;
    }
    btn.dataset.armed=''; btn.disabled=true; btn.textContent='删除中…';
    const keys=[...selected];
    let ok=0, fail=0;
    for(const key of keys){
      try{
        const r=await fetch('/api/delete',{
          method:'POST', headers:{'Content-Type':'application/json'},
          body:JSON.stringify(Object.assign({key:key}, authFields()))
        });
        if(r.status===404) throw new Error('预览模式无后端');
        const data=await r.json().catch(()=>({}));
        if(r.status===401){ authExpired(); throw new Error('登录已过期，请重新输入密码'); }
        if(!r.ok) throw new Error(data.error||('删除失败 '+r.status));
        cloudItems=cloudItems.filter(x=>x.key!==key);
        selected.delete(key);
        ok++;
        btn.textContent='删除中 '+ok+'/'+keys.length+'…';
      }catch(e){ fail++; toast(key.split('/').pop()+'：'+e.message,'err'); }
    }
    btn.disabled=false; btn.textContent='删除';
    renderCloud($('cloudSearch').value); updateBatchBar();
    if(ok) toast('已删除 '+ok+' 个文件'+(fail?'，失败 '+fail+' 个':''), ok&&!fail?'ok':'');
  });

  // ================= 拖拽移动到目录 =================
  function dirName(d){ return {img:'图片',video:'视频',other:'其他'}[d]||d; }
  [...$('dirTabs').children].forEach(tab=>{
    const dir=tab.dataset.dir;
    if(dir==='all') return; // 「全部」不是真实目录，不能作为移动目标
    tab.addEventListener('dragover',e=>{
      if(!dragKeys||!dragKeys.length) return;
      e.preventDefault(); e.dataTransfer.dropEffect='move';
      tab.classList.add('dropover');
    });
    tab.addEventListener('dragleave',()=>tab.classList.remove('dropover'));
    tab.addEventListener('drop',e=>{
      e.preventDefault(); tab.classList.remove('dropover');
      if(dragKeys&&dragKeys.length) moveFiles(dragKeys, dir);
    });
  });
  // 移动 = 后端 copy + delete（复用 /api/rename 的 dir 参数）
  async function moveFiles(keys, dir){
    const targets=cloudItems.filter(f=>keys.includes(f.key) && f.key.split('/')[1]!==dir);
    if(!targets.length){ toast('文件已在「'+dirName(dir)+'」目录'); return; }
    let ok=0, fail=0;
    for(const f of targets){
      try{
        const r=await fetch('/api/rename',{
          method:'POST', headers:{'Content-Type':'application/json'},
          body:JSON.stringify(Object.assign({key:f.key, dir:dir}, authFields()))
        });
        if(r.status===404) throw new Error('预览模式无后端，移动需部署后使用');
        const data=await r.json().catch(()=>({}));
        if(r.status===401){ authExpired(); throw new Error('登录已过期，请重新输入密码'); }
        if(!r.ok) throw new Error(data.error||('移动失败 '+r.status));
        f.key=data.key; f.url=data.url;
        selected.delete(data.oldKey||'');
        ok++;
      }catch(e){ fail++; toast(f.key.split('/').pop()+'：'+e.message,'err'); }
    }
    updateBatchBar();
    // 目录标签页按服务端前缀过滤：移动后当前目录视图需重新加载
    if(curDir!=='all') loadCloud(false); else renderCloud($('cloudSearch').value);
    if(ok) toast('已移动 '+ok+' 个文件到「'+dirName(dir)+'」'+(fail?'，失败 '+fail+' 个':''), ok&&!fail?'ok':'');
  }

  function prependCloudItem(f){
    if(curDir!=='all' && TYPE_DIR[f.type]!==curDir) return; // 不在当前目录就不插入
    cloudItems.unshift(f);
    renderCloud($('cloudSearch').value);
  }

  async function loadCloud(append){
    const hint=$('cloudHint'), moreBtn=$('cloudMore'), list=$('cloudList');
    hint.style.display='none'; moreBtn.style.display='none';
    if(!append){
      list.innerHTML=Array.from({length:8},()=>'<div class="skel"></div>').join('');
      cloudItems=[]; cloudToken='';
      selected.clear(); updateBatchBar(); // 目录切换/刷新后旧选择已失效
    }
    try{
      const r=await fetch('/api/list',{
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify(Object.assign({token:append?cloudToken:'', dir:curDir}, authFields()))
      });
      if(r.status===404){
        list.innerHTML='';
        hint.style.display='block';
        hint.textContent='静态预览模式：云端文件需部署后使用';
        return;
      }
      if(r.status===401){ authExpired(); return; }
      const data=await r.json();
      if(!r.ok) throw new Error(data.error||('服务端错误 '+r.status));
      cloudItems=cloudItems.concat(data.files||[]);
      cloudToken=data.nextToken||'';
      renderCloud($('cloudSearch').value);
      moreBtn.style.display=data.truncated?'inline-block':'none';
    }catch(e){
      list.innerHTML='';
      hint.style.display='block';
      const offline=/failed to fetch|networkerror|load failed/i.test(e.message||'');
      hint.textContent=offline?'静态预览模式：云端文件需部署后使用':'加载失败：'+e.message;
    }
  }

  $('cloudRefresh').addEventListener('click',()=>loadCloud(false));
  $('cloudMore').addEventListener('click',()=>loadCloud(true));
  $('cloudSearch').addEventListener('input',e=>renderCloud(e.target.value));
  const sortSel=$('cloudSort');
  sortSel.value=['time_desc','time_asc','size_desc','size_asc'].includes(curSort)?curSort:'time_desc';
  sortSel.addEventListener('change',()=>{
    curSort=sortSel.value; localStorage.setItem(SORT_KEY,curSort);
    renderCloud($('cloudSearch').value);
  });
  applyView();

  // ================= 灯箱 =================
  let lbCurrent=null;
  const lbRenameRow=$('lbRenameRow'), lbRenameInput=$('lbRenameInput');
  function closeRename(){ lbRenameRow.style.display='none'; lbMeta.style.display=''; }
  function openLightbox(f){
    lbCurrent=f;
    closeRename();
    const t=f.type||fileTypeOf(f.key);
    const name=f.key.split('/').pop();
    const u=escapeHtml(f.url);
    if(t==='image'){
      lbMedia.innerHTML='<img src="'+u+'" alt="">';
      $('lbOpen').style.display='none';
    }else if(t==='video'){
      lbMedia.innerHTML='<video controls playsinline src="'+u+'"></video>';
      $('lbOpen').style.display='none';
    }else{
      lbMedia.innerHTML='<div class="lb-file"><div class="fico">'+fileIcon(f.key)+'</div><div class="fname">'+escapeHtml(name)+'</div></div>';
      $('lbOpen').style.display='';
    }
    $('lbCopy').textContent='复制'+({'url':'链接','md':'Markdown','html':'HTML','bbcode':'BBCode'}[curFmt]||'链接');
    lbMeta.innerHTML=escapeHtml(f.key)+'<br>'+(f.size?fmtSize(f.size)+' · ':'')+(f.time?new Date(f.time).toLocaleString():'');
    resetDeleteBtn();
    lightbox.classList.add('show');
  }
  function closeLightbox(){
    lightbox.classList.remove('show');
    lbMedia.innerHTML=''; // 停止视频播放
    closeRename();
    lbCurrent=null;
  }
  $('lbClose').addEventListener('click',closeLightbox);
  lightbox.addEventListener('click',e=>{ if(e.target===lightbox) closeLightbox(); });
  window.addEventListener('keydown',e=>{ if(e.key==='Escape'){ closeQr(); closeLightbox(); } });
  $('lbCopy').addEventListener('click',()=>{ if(lbCurrent) copyText(formatLink(lbCurrent), FMT_LABEL[curFmt]); });
  // 格式按钮：选中格式、记住选择，并立即按该格式复制当前文件
  lbFmtRow.addEventListener('click',e=>{
    const b=e.target.closest('.fmt-btn');
    if(!b||!lbCurrent) return;
    curFmt=b.dataset.fmt; localStorage.setItem(FMT_KEY,curFmt);
    syncFmtBtns();
    $('lbCopy').textContent='复制'+({'url':'链接','md':'Markdown','html':'HTML','bbcode':'BBCode'}[curFmt]||'链接');
    copyText(formatLink(lbCurrent), FMT_LABEL[curFmt]);
  });

  // ================= 分享二维码（本地生成，不经任何第三方服务，直链不出本机） =================
  const qrModal=$('qrModal');
  function closeQr(){ qrModal.classList.remove('show'); }
  $('lbQr').addEventListener('click',()=>{
    if(!lbCurrent) return;
    if(typeof qrcode==='undefined'){ toast('二维码组件未加载','err'); return; }
    try{
      qrcode.stringToBytes=qrcode.stringToBytesFuncs['UTF-8']; // 默认编码只支持 Latin-1，切到 UTF-8 以支持中文文件名
      const qr=qrcode(0,'M'); qr.addData(lbCurrent.url); qr.make();
      $('qrImg').src=qr.createDataURL(7,4);
      $('qrUrl').textContent=lbCurrent.url;
      qrModal.dataset.url=lbCurrent.url;
      qrModal.classList.add('show');
    }catch(e){ toast('二维码生成失败：'+e.message,'err'); }
  });
  $('qrClose').addEventListener('click',closeQr);
  qrModal.addEventListener('click',e=>{ if(e.target===qrModal) closeQr(); });
  $('qrCopy').addEventListener('click',()=>{ if(qrModal.dataset.url) copyText(qrModal.dataset.url,'链接'); });
  $('lbOpen').addEventListener('click',()=>{ if(lbCurrent) window.open(lbCurrent.url,'_blank','noopener,noreferrer'); });
  // ================= 重命名 =================
  $('lbRename').addEventListener('click',()=>{
    if(!lbCurrent) return;
    lbRenameInput.value=lbCurrent.key.split('/').pop();
    lbMeta.style.display='none'; lbRenameRow.style.display='flex';
    lbRenameInput.focus(); lbRenameInput.select();
  });
  $('lbRenameCancel').addEventListener('click',closeRename);
  lbRenameInput.addEventListener('keydown',e=>{
    if(e.key==='Enter') doRename();
    if(e.key==='Escape') closeRename();
  });
  $('lbRenameOk').addEventListener('click',doRename);
  async function doRename(){
    if(!lbCurrent) return;
    const name=lbRenameInput.value.trim();
    // 与服务端一致的白名单校验：中文 / 字母数字 / 点 / 下划线 / 连字符，保证改名后 list/delete 仍正常
    if(!/^[A-Za-z0-9._\-一-鿿㐀-䶿가-힯ㄱ-ㅣ぀-ヿ]+$/.test(name) || name.startsWith('.') || name.includes('..') || name.length>200){
      toast('文件名只允许中日韩文字、字母、数字、点、下划线、连字符','err'); return;
    }
    const oldKey=lbCurrent.key;
    if(name===oldKey.split('/').pop()){ closeRename(); return; }
    const btn=$('lbRenameOk'); btn.disabled=true; btn.textContent='改名中…';
    try{
      const r=await fetch('/api/rename',{
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify(Object.assign({key:oldKey, name:name}, authFields()))
      });
      if(r.status===404) throw new Error('预览模式无后端，重命名需部署后使用');
      const data=await r.json().catch(()=>({}));
      if(r.status===401){ authExpired(); throw new Error('登录已过期，请重新输入密码'); }
      if(!r.ok) throw new Error(data.error||('重命名失败 '+r.status));
      // 更新内存中的条目与灯箱显示（新 key / 新直链）
      const it=cloudItems.find(x=>x.key===oldKey);
      if(it){ it.key=data.key; it.url=data.url; }
      lbCurrent.key=data.key; lbCurrent.url=data.url;
      closeRename();
      renderCloud($('cloudSearch').value);
      lbMeta.innerHTML=escapeHtml(data.key)+'<br>'+(lbCurrent.size?fmtSize(lbCurrent.size)+' · ':'')+(lbCurrent.time?new Date(lbCurrent.time).toLocaleString():'');
      const media=lbMedia.querySelector('img,video');
      if(media) media.src=data.url;
      toast('已重命名为 '+name,'ok');
    }catch(e){
      toast(e.message,'err');
    }finally{
      btn.disabled=false; btn.textContent='确定';
    }
  }
  // 下载：直链 + download 文件名提示（target=_blank 防止图片/视频把当前页导航走）。
  // 网页 JS 无法检测 IDM 这类下载器插件，但 IDM 是靠 hook 浏览器的真实下载/导航请求来接管的——
  // 只有发起到真实 URL 的请求它才抓得到；之前的 fetch→Blob 本地下载它完全感知不到，故弃用 Blob 方案。
  // 文件名本就在 URL 路径里（keepName 开启时为原名），下载器保存时不会丢名。
  $('lbDownload').addEventListener('click',()=>{
    if(!lbCurrent) return;
    const a=document.createElement('a');
    a.href=lbCurrent.url;
    a.download=lbCurrent.key.split('/').pop();
    a.target='_blank'; a.rel='noopener noreferrer';
    document.body.appendChild(a); a.click(); a.remove();
    toast('已发起下载（装了 IDM 等下载器会自动接管）','ok');
  });

  function resetDeleteBtn(){
    const b=$('lbDelete');
    b.textContent='删除文件'; b.classList.remove('confirm'); b.dataset.armed='';
  }
  $('lbDelete').addEventListener('click',async ()=>{
    if(!lbCurrent) return;
    const b=$('lbDelete');
    if(!b.dataset.armed){
      b.dataset.armed='1'; b.textContent='再点一次确认删除'; b.classList.add('confirm');
      setTimeout(resetDeleteBtn, 3000);
      return;
    }
    b.disabled=true; b.textContent='删除中…';
    try{
      const r=await fetch('/api/delete',{
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify(Object.assign({key:lbCurrent.key}, authFields()))
      });
      const data=await r.json().catch(()=>({}));
      if(r.status===401){ authExpired(); throw new Error('登录已过期，请重新输入密码'); }
      if(!r.ok) throw new Error(data.error||('删除失败 '+r.status));
      cloudItems=cloudItems.filter(x=>x.key!==lbCurrent.key);
      renderCloud($('cloudSearch').value);
      closeLightbox();
      toast('已从 OSS 删除','ok');
    }catch(e){
      toast(e.message,'err');
    }finally{
      b.disabled=false; resetDeleteBtn();
    }
  });

  // ================= 本机历史 =================
  function getHist(){ try{return JSON.parse(localStorage.getItem(HIST_KEY))||[]}catch(e){return[]} }
  function addHistory(url){
    const h=getHist(); h.unshift({url:url, t:Date.now()});
    localStorage.setItem(HIST_KEY, JSON.stringify(h.slice(0,60)));
    renderHist();
  }
  function renderHist(){
    const h=getHist(), card=$('historyCard'), list=$('historyList');
    if(!h.length){ card.style.display='none'; return; }
    card.style.display='block'; list.innerHTML='';
    h.forEach(it=>{
      const d=document.createElement('div');
      d.className='gitem';
      const t=fileTypeOf(it.url.split('?')[0]);
      if(t==='image') d.innerHTML='<img loading="lazy" src="'+escapeHtml(it.url)+'">';
      else if(t==='video') d.innerHTML='<div class="ftile"><div class="fico">🎬</div><div class="fext">video</div></div>';
      else d.innerHTML='<div class="ftile"><div class="fico">'+fileIcon(it.url)+'</div><div class="fext">'+escapeHtml((it.url.split('.').pop()||'file').slice(0,6))+'</div></div>';
      d.innerHTML+='<div class="mask"><span>点击复制链接</span></div>';
      d.addEventListener('click',()=>copyText(formatLink({url:it.url, key:it.url.split('?')[0].split('/').map(decodeURIComponent).join('/'), type:t}), FMT_LABEL[curFmt]));
      list.appendChild(d);
    });
  }
  $('clearHist').addEventListener('click',()=>{ localStorage.removeItem(HIST_KEY); renderHist(); toast('历史已清空'); });
  renderHist();

  // 测试钩子（仅本地截图验证用）
  window.__test={
    demo:function(v){
      lockScreen.classList.add('hidden'); mainApp.classList.add('unlocked');
      cloudItems=[]; var now=Date.now();
      for(var i=0;i<14;i++){ var h=200+((i*37)%160);
        cloudItems.push({key:'upweb/img/2026/08/25/测试图片-'+i+'.jpg',url:'https://picsum.photos/seed/yw'+i+'/300/'+h,size:1024*(100+i*40),time:new Date(now-i*3600000*5).toISOString()}); }
      curView=v; applyView(); renderCloud('');
    },
    batch:function(){ this.demo('grid'); setBatch(true); selected.add(cloudItems[0].key); selected.add(cloudItems[2].key); selected.add(cloudItems[5].key); updateBatchBar(); renderCloud(''); },
    rename:function(){ this.demo('grid'); lbCurrent=cloudItems[0]; openLightbox(cloudItems[0]); document.getElementById('lbRename').click(); },
    qr:function(){ this.demo('grid'); lbCurrent=cloudItems[0]; openLightbox(cloudItems[0]); document.getElementById('lbQr').click(); },
    drag:function(){ this.demo('grid'); document.querySelectorAll('#dirTabs .tab')[2].classList.add('dropover'); },
    // 上传面板：'run' 进行中（暂停/取消+速度显示），'done' 完成态（成功/失败混合+清空），'paused' 暂停态（继续/取消）
    panel:function(state){
      this.demo('grid');
      var mk=function(n){ return new File(['x'],n,{type:'application/octet-stream'}); };
      var a=mk('已完成的资料包.zip'), b=mk('演示视频-分片上传中.mp4');
      var ia={file:a, el:buildQItem(a), state:'done', lastPct:100}, ib={file:b, el:buildQItem(b), state:'uploading', lastPct:54};
      queue.appendChild(ia.el); queue.appendChild(ib.el);
      setQ(ia,100,'✓ 完成 · 1 KB → upweb/other','ok'); setQControls(ia,'done');
      if(state==='done'){
        ib.state='err'; ib.lastPct=100;
        setQ(ib,100,'✗ 网络中断（若反复出现，请检查桶 CORS 配置）','err'); setQControls(ib,'err');
      }else if(state==='paused'){
        ib.state='paused'; ib.el.classList.add('paused');
        setQ(ib,54,'⏸ 已暂停 · 点「继续」接着传'); setQControls(ib,'paused');
      }else{
        setQ(ib,54,'分片 3/6 上传中 · 54% · 3.2 MB/s'); setQControls(ib,'uploading');
        uploading=true;
      }
      updateUpHead();
    }
  };
})();
