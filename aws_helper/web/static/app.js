// 通用工具：toast、请求封装、任务轮询
function toast(msg, kind) {
  const box = document.getElementById('toast');
  if (!box) return alert(msg);
  const el = document.createElement('div');
  el.className = kind || '';
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => el.remove(), 5200);
}

async function api(url, opts) {
  opts = opts || {};
  const init = { method: opts.method || 'GET', headers: {} };
  if (opts.json) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.json);
  }
  if (opts.form) init.body = opts.form;
  const resp = await fetch(url, init);
  let data;
  try {
    data = await resp.json();
  } catch (e) {
    throw new Error('服务端返回了非 JSON 响应 (HTTP ' + resp.status + ')');
  }
  if (!resp.ok || data.ok === false) {
    throw new Error(data.error || data.detail || ('HTTP ' + resp.status));
  }
  return data;
}

// 任务进度弹窗
const Progress = {
  el: null,
  open(title) {
    if (!this.el) {
      this.el = document.createElement('div');
      this.el.className = 'mask';
      this.el.innerHTML =
        '<div class="box"><h2 id="pg-title"></h2>' +
        '<div class="bar"><i id="pg-bar"></i></div>' +
        '<div class="steps" id="pg-steps"></div>' +
        '<div class="row end mt" id="pg-foot"></div></div>';
      document.body.appendChild(this.el);
    }
    document.getElementById('pg-title').textContent = title;
    document.getElementById('pg-steps').innerHTML = '<div>准备中…</div>';
    document.getElementById('pg-bar').style.width = '5%';
    document.getElementById('pg-foot').innerHTML = '';
    this.el.classList.add('on');
  },
  update(task) {
    const steps = document.getElementById('pg-steps');
    steps.innerHTML = task.steps.map(s => '<div>' + escapeHtml(s) + '</div>').join('');
    steps.scrollTop = steps.scrollHeight;
    const pct = task.status === 'done' ? 100 : Math.min(92, 8 + task.steps.length * 11);
    document.getElementById('pg-bar').style.width = pct + '%';
  },
  finish(html) {
    document.getElementById('pg-foot').innerHTML =
      (html || '') + '<button class="primary" onclick="Progress.close()">关闭</button>';
  },
  close() {
    if (this.el) this.el.classList.remove('on');
    if (typeof onProgressClose === 'function') onProgressClose();
  }
};

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// 轮询任务直到结束，resolve 完成后的 task 对象
function watchTask(taskId, title) {
  Progress.open(title);
  return new Promise((resolve, reject) => {
    const timer = setInterval(async () => {
      try {
        const data = await api('/api/tasks/' + taskId);
        const task = data.task;
        Progress.update(task);
        if (task.status === 'running') return;
        clearInterval(timer);
        if (task.status === 'done') resolve(task);
        else reject(new Error(task.error || '任务失败'));
      } catch (e) {
        clearInterval(timer);
        reject(e);
      }
    }, 1200);
  });
}
