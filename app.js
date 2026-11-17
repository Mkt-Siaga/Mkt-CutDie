/* Mkt-CutDie — controle de facas e fichas (Grupo Siaga)
   Todo o conteúdo em v/ é cifrado (AES-256-GCM). A senha libera a chave via PBKDF2. */
(() => {
  'use strict';
  const $ = s => document.querySelector(s);
  const $$ = s => [...document.querySelectorAll(s)];
  const te = new TextDecoder();
  const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const b64e = u => btoa(String.fromCharCode(...new Uint8Array(u)));
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const store = {
    get: (k, s = sessionStorage) => { try { return s.getItem(k); } catch { return null; } },
    set: (k, v, s = sessionStorage) => { try { s.setItem(k, v); } catch { /* sem storage */ } },
    del: (k, s = sessionStorage) => { try { s.removeItem(k); } catch { /* sem storage */ } },
  };

  let chave = null;          // CryptoKey de dados
  let D = null;              // dados decifrados
  const blobs = new Map();   // id -> objectURL
  let indice = new Map();    // código -> item
  let ultimos = [];          // itens da consulta atual

  // ---------------- cripto ----------------
  async function abreCofre(senha) {
    const cofre = await fetch('v/cofre.json', { cache: 'no-store' }).then(r => r.json());
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(senha), 'PBKDF2', false, ['deriveKey']);
    const kek = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64d(cofre.salt), iterations: cofre.iter },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(cofre.iv) }, kek, b64d(cofre.chave));
    return raw;
  }
  const importaChave = raw => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  async function decifra(url) {
    const buf = new Uint8Array(await fetch(url).then(r => { if (!r.ok) throw new Error(r.status); return r.arrayBuffer(); }));
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.subarray(0, 12) }, chave, buf.subarray(12));
  }
  async function urlDe(id) {
    if (blobs.has(id)) return blobs.get(id);
    const meta = D.arquivos[id];
    const u = URL.createObjectURL(new Blob([await decifra(`v/${id}.bin`)], { type: meta.tipo }));
    blobs.set(id, u);
    return u;
  }

  // ---------------- login ----------------
  async function entra(raw) {
    chave = await importaChave(raw);
    D = JSON.parse(te.decode(await decifra('v/dados.bin')));
    indice = new Map();
    for (const it of D.itens) for (const c of [it.siaga, it.durax, it.durabem, it.ean, it.dun]) if (c) indice.set(c.toUpperCase(), it);
    $('#login').hidden = true;
    $('#app').hidden = false;
    montaAcervo();
    montaFacas();
    const salvo = store.get('cutdie.skus', localStorage);
    if (salvo) { $('#skus').value = salvo; busca(); }
  }

  $('#form-login').addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('#btn-entrar');
    btn.disabled = true; btn.textContent = 'Verificando…'; $('#login-erro').textContent = '';
    try {
      const raw = await abreCofre($('#senha').value);
      store.set('cutdie.k', b64e(raw));
      $('#senha').value = '';
      await entra(raw);
    } catch (err) {
      $('#login-erro').textContent = 'Senha incorreta.';
    } finally { btn.disabled = false; btn.textContent = 'Entrar'; }
  });

  $('#btn-sair').addEventListener('click', () => {
    store.del('cutdie.k');
    blobs.forEach(u => URL.revokeObjectURL(u));
    location.reload();
  });

  // ---------------- abas ----------------
  $$('.tab').forEach(t => t.addEventListener('click', () => {
    $$('.tab').forEach(x => x.classList.toggle('is-on', x === t));
    for (const p of ['consulta', 'acervo', 'facas']) $('#tab-' + p).hidden = p !== t.dataset.tab;
  }));

  // ---------------- consulta ----------------
  const titulo = it => {
    const d = it.descricao.replace(/\s*-\s*TEMPERATURA:.*$/i, '').replace(/\s*-\s*BRANCO$/i, '');
    return d.charAt(0) + d.slice(1).toLowerCase().replace(/\bled\b/g, 'LED').replace(/(\d+)w\b/g, '$1W');
  };
  const luz = it => it.temp ? `${it.temp} (${/3000|3500/.test(it.temp) ? 'quente' : 'fria'})` : '';

  function busca() {
    const raw = $('#skus').value;
    store.set('cutdie.skus', raw, localStorage);
    const cods = [...new Set(raw.split(/[\s,;]+/).map(s => s.trim().toUpperCase()).filter(Boolean))];
    const achados = [], nao = [];
    for (const c of cods) { const it = indice.get(c); if (it) { if (!achados.includes(it)) achados.push(it); } else nao.push(c); }
    ultimos = achados;
    const comFaca = achados.filter(i => i.faca).length;
    $('#resumo').innerHTML = cods.length
      ? `${achados.length} SKU(s) encontrado(s) · ${comFaca} com faca · ${achados.length - comFaca} sem faca` +
        (nao.length ? `<br><span class="nao">Não encontrado(s): ${nao.map(esc).join(', ')}</span>` : '')
      : '';
    $('#btn-baixar-facas').disabled = !comFaca;
    $('#resultados').innerHTML = achados.map(cardHtml).join('');
    achados.forEach(async it => { const img = document.querySelector(`[data-img="${it.siaga}"]`); if (img) img.src = await urlDe(it.img); });
  }

  function cardHtml(it) {
    const cods = [`<span class="cod sg">SG ${esc(it.siaga)}</span>`];
    if (it.durax) cods.push(`<span class="cod">${esc(it.durax)}</span>`);
    if (it.durabem) cods.push(`<span class="cod">${esc(it.durabem)}</span>`);
    if (it.ean) cods.push(`<span class="cod">EAN ${esc(it.ean)}</span>`);
    const pdfs = it.fichasPdf.map(f => `<button class="btn btn-ghost btn-sm" data-pdf="${f.id}" data-titulo="Ficha ${esc(f.marca)} · ${esc(f.marca === 'Durax' ? it.durax : it.siaga)}">PDF ${esc(f.marca)}</button>`).join('');
    return `<article class="card">
      <div class="foto"><img data-img="${esc(it.siaga)}" alt=""></div>
      <div>
        <div class="codes">${cods.join('')}</div>
        <h3>${esc(titulo(it))}</h3>
        <div class="meta">${[it.potencia, it.lumens?.toLowerCase(), luz(it), it.caixaInd && 'caixa ' + it.caixaInd].filter(Boolean).map(esc).join(' · ')}</div>
        <div class="meta" style="margin-top:4px">${it.faca
          ? `<span class="tag ok">Faca</span> ${esc(it.faca.nome)}`
          : `<span class="tag no">Sem faca</span> ${it.integral ? 'Painel plástico integral: caixa diferente, sem faca no repositório.' : 'Não há faca no repositório para este item.'}`}</div>
        ${/parciais|sem cadastro/.test(it.fonte) ? `<div class="aviso">Ficha com dados parciais (${esc(it.fonte)}).</div>` : ''}
      </div>
      <div class="acoes">
        <div class="grupo"><button class="btn btn-primary btn-sm" data-ficha="${esc(it.siaga)}">Ficha técnica</button></div>
        ${it.faca ? `<div class="grupo"><button class="btn btn-ghost btn-sm" data-pdf="${it.faca.id}" data-titulo="${esc(it.faca.nome)}">Ver faca</button><button class="btn btn-ghost btn-sm" data-baixar="${it.faca.id}">Baixar faca</button></div>` : ''}
        ${pdfs ? `<div class="grupo">${pdfs}</div>` : ''}
      </div>
    </article>`;
  }

  $('#btn-buscar').addEventListener('click', busca);
  $('#skus').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) busca(); });
  $('#btn-limpar').addEventListener('click', () => { $('#skus').value = ''; busca(); $('#skus').focus(); });
  $('#btn-baixar-facas').addEventListener('click', async () => {
    const ids = [...new Set(ultimos.filter(i => i.faca).map(i => i.faca.id))];
    for (const id of ids) { await baixa(id); await new Promise(r => setTimeout(r, 400)); }
  });

  // delegação de cliques (cards, tabelas)
  document.addEventListener('click', async e => {
    const b = e.target.closest('[data-ficha],[data-pdf],[data-baixar],[data-add]');
    if (!b) return;
    if (b.dataset.ficha) abreFicha(indice.get(b.dataset.ficha.toUpperCase()));
    else if (b.dataset.pdf) abrePdf(b.dataset.pdf, b.dataset.titulo);
    else if (b.dataset.baixar) baixa(b.dataset.baixar);
    else if (b.dataset.add) {
      const atual = $('#skus').value.trim();
      const cods = b.dataset.add.split(',');
      $('#skus').value = [atual, ...cods.filter(c => !atual.toUpperCase().split(/[\s,;]+/).includes(c))].filter(Boolean).join('\n');
      $$('.tab')[0].click(); busca();
    }
  });

  async function baixa(id) {
    const a = document.createElement('a');
    a.href = await urlDe(id); a.download = D.arquivos[id].nome;
    document.body.appendChild(a); a.click(); a.remove();
  }

  // ---------------- visualizador ----------------
  const viewer = $('#viewer');
  $('#viewer-fechar').addEventListener('click', () => viewer.close());
  viewer.addEventListener('close', () => { if (!viewer.open) $('#viewer-corpo').innerHTML = ''; });

  async function abrePdf(id, tit) {
    $('#viewer-titulo').textContent = tit || D.arquivos[id].nome;
    $('#viewer-imprimir').hidden = true;
    const a = $('#viewer-baixar'); a.hidden = false; a.download = D.arquivos[id].nome;
    $('#viewer-corpo').innerHTML = '<p style="color:#fff;padding:20px">Abrindo…</p>';
    viewer.showModal();
    const u = await urlDe(id);
    a.href = u;
    $('#viewer-corpo').innerHTML = `<iframe src="${u}" title="${esc(tit)}"></iframe>`;
  }

  async function abreFicha(it) {
    const html = fichaHtml(it, await urlDe(it.img));
    $('#viewer-titulo').textContent = `Ficha técnica · ${it.siaga}${it.durax ? ' / ' + it.durax : ''}`;
    $('#viewer-baixar').hidden = true;
    $('#viewer-imprimir').hidden = false;
    $('#viewer-corpo').innerHTML = html;
    $('#area-impressao').innerHTML = html;
    viewer.showModal();
  }
  $('#viewer-imprimir').addEventListener('click', () => {
    const t = document.title; document.title = $('#viewer-titulo').textContent.replace(/[·/]/g, '-');
    window.print(); document.title = t;
  });

  // ---------------- ficha técnica ----------------
  const linha = (k, v) => v ? `<tr><td class="k">${esc(k)}</td><td class="v">${esc(v)}</td></tr>` : '';
  const cap = s => s ? s.charAt(0) + s.slice(1).toLowerCase() : '';

  function fichaHtml(it, img) {
    const chips = [
      [it.potencia, 'Potência'], [it.lumens && it.lumens.replace(/\s*LUMENS/i, ' lm'), 'Fluxo luminoso'],
      [it.temp, /3000|3500/.test(it.temp) ? 'Luz quente' : 'Luz fria'], [it.tensao && it.tensao.replace(/\s*\(.*\)/, ''), it.tensao?.match(/\((.*)\)/)?.[1] || 'Tensão'],
      [it.ip, 'Proteção'], [it.garantia && cap(it.garantia), 'Garantia'],
    ].filter(c => c[0]);
    const dataBr = new Date().toLocaleDateString('pt-BR');
    return `<div class="folha">
      <header><img src="logo-siaga.svg" alt="Grupo Siaga"><div class="t"><b>Ficha técnica</b>Iluminação LED</div></header>
      <div class="corpo">
        <section class="hero">
          <div class="ft"><img src="${img}" alt=""></div>
          <div>
            <span class="sku">SG ${esc(it.siaga)}</span>
            <h1>${esc(titulo(it))}</h1>
            <p class="sub">${esc(it.descricao)}</p>
            <div class="chips">${chips.map(c => `<div class="chip"><b>${esc(c[0])}</b><span>${esc(c[1])}</span></div>`).join('')}</div>
          </div>
        </section>

        <h2>Identificação</h2>
        <table>
          ${linha('Código Siaga', it.siaga)}${linha('Código Durax', it.durax)}${linha('Código Durabem', it.durabem)}
          ${linha('Família', it.familia)}${linha('Descrição (EN)', it.descricaoEn)}
          ${linha('NCM', it.ncm)}${linha('CEST', it.cest)}${linha('Origem', cap(it.origem))}
        </table>

        <div class="cols">
          <div><h2>Especificações elétricas</h2><table>
            ${linha('Potência', it.potencia)}${linha('Fluxo luminoso', it.lumens && it.lumens.toLowerCase())}
            ${linha('Temperatura de cor', luz(it))}${linha('Tensão', it.tensao)}${linha('Frequência', it.frequencia)}
            ${linha('Fator de potência', it.fp)}${linha('Corrente 127V', it.corrente127)}${linha('Corrente 220V', it.corrente220)}
            ${linha('Dimerizável', it.dimerizavel)}
          </table></div>
          <div><h2>Características</h2><table>
            ${linha('Instalação', cap(it.instalacao))}${linha('Formato', cap(it.formato))}${linha('Cor do produto', it.corProduto)}
            ${linha('Material', it.material)}${linha('Grau de proteção', it.ip)}${linha('IRC (CRI)', it.cri)}
            ${linha('Garantia', cap(it.garantia))}${linha('Validade', it.validade)}
          </table></div>
        </div>

        <h2>Dimensões e embalagem</h2>
        <table>
          ${linha('Produto', it.tamanho)}${linha('Caixa individual', it.caixaInd)}
          ${linha('Caixa master', [it.medidasMaster, it.qtdMaster && it.qtdMaster.toLowerCase()].filter(Boolean).join(' · '))}
          ${linha('Peso da master', [it.pesoLiq && it.pesoLiq + ' líquido', it.pesoBruto && it.pesoBruto + ' bruto'].filter(Boolean).join(' · '))}
          ${linha('CBM master', it.cbm)}
        </table>
        <p class="faca-ref"><b>Faca da embalagem:</b> ${it.faca ? esc(it.faca.nome) : 'não há faca no repositório para este item'}</p>

        ${(it.ean || it.dun) ? `<h2>Códigos de barras</h2><div class="bars">
          ${it.ean ? `<div class="bar"><div class="t">EAN-13 · unidade</div><div class="n">${esc(it.ean)}</div>${ean13Svg(it.ean)}</div>` : ''}
          ${it.dun ? `<div class="bar"><div class="t">DUN-14 · caixa master</div><div class="n">${esc(it.dun)}</div>${itf14Svg(it.dun)}</div>` : ''}
        </div>` : ''}
      </div>
      <footer><div><b>Grupo Siaga</b> · ficha gerada pelo Mkt-CutDie<br>Fonte: ${esc(it.fonte)}. Imagem ilustrativa da família. Especificações sujeitas a alteração.</div>
        <div style="text-align:right">SG ${esc(it.siaga)}<br>Emitida em ${dataBr}</div></footer>
    </div>`;
  }

  // EAN-13
  function ean13Svg(code) {
    if (!/^\d{13}$/.test(code)) return '';
    const L = ['0001101', '0011001', '0010011', '0111101', '0100011', '0110001', '0101111', '0111011', '0110111', '0001011'];
    const G = L.map(p => [...p].map(b => b === '1' ? '0' : '1').reverse().join(''));
    const R = L.map(p => [...p].map(b => b === '1' ? '0' : '1').join(''));
    const par = ['LLLLLL', 'LLGLGG', 'LLGGLG', 'LLGGGL', 'LGLLGG', 'LGGLLG', 'LGGGLL', 'LGLGLG', 'LGLGGL', 'LGGLGL'][+code[0]];
    let bits = '101';
    for (let i = 1; i <= 6; i++) bits += (par[i - 1] === 'L' ? L : G)[+code[i]];
    bits += '01010';
    for (let i = 7; i <= 12; i++) bits += R[+code[i]];
    bits += '101';
    return barsSvg(bits);
  }
  // ITF-14
  function itf14Svg(code) {
    if (!/^\d{14}$/.test(code)) return '';
    const P = ['nnwwn', 'wnnnw', 'nwnnw', 'wwnnn', 'nnwnw', 'wnwnn', 'nwwnn', 'nnnww', 'wnnwn', 'nwnwn'];
    let bits = '1010';
    for (let i = 0; i < 14; i += 2) {
      const a = P[+code[i]], b = P[+code[i + 1]];
      for (let j = 0; j < 5; j++) bits += (a[j] === 'w' ? '111' : '1') + (b[j] === 'w' ? '000' : '0');
    }
    bits += '11101';
    return barsSvg(bits);
  }
  function barsSvg(bits) {
    let x = 0, r = '';
    while (x < bits.length) {
      if (bits[x] === '1') { let w = 1; while (bits[x + w] === '1') w++; r += `<rect x="${x}" y="0" width="${w}" height="40"/>`; x += w; } else x++;
    }
    return `<svg viewBox="0 0 ${bits.length} 40" preserveAspectRatio="none" fill="#171717">${r}</svg>`;
  }

  // ---------------- acervo ----------------
  function montaAcervo() {
    const n = D.itens.length, cf = D.itens.filter(i => i.faca).length;
    $('#kpis').innerHTML = [[n, 'SKUs no acervo'], [cf, 'com faca'], [n - cf, 'sem faca'], [D.facas.length, 'facas no repositório']]
      .map(([v, l]) => `<div class="kpi"><b>${v}</b><span>${l}</span></div>`).join('');
    desenhaTabela();
  }
  function desenhaTabela() {
    const q = $('#filtro').value.trim().toUpperCase(), ff = $('#filtro-faca').value;
    const rows = D.itens.filter(it => (!q || [it.siaga, it.durax, it.durabem, it.ean, it.descricao, it.familia].join(' ').toUpperCase().includes(q))
      && (!ff || (ff === 'com') === !!it.faca));
    $('#tabela').innerHTML = `<thead><tr><th>Siaga</th><th>Durax</th><th>Descrição</th><th>Caixa ind.</th><th>Faca</th><th>PDFs</th><th></th></tr></thead><tbody>` +
      rows.map(it => `<tr>
        <td class="mono">${esc(it.siaga)}</td><td class="mono">${esc(it.durax || '—')}</td>
        <td>${esc(it.descricao)}</td><td class="mono">${esc(it.caixaInd || '—')}</td>
        <td>${it.faca ? `<span class="tag ok" title="${esc(it.faca.nome)}">Sim</span>` : '<span class="tag no">Não</span>'}</td>
        <td>${it.fichasPdf.length || ''}</td>
        <td><button class="btn btn-ghost btn-sm" data-add="${esc(it.siaga)}">+ Consulta</button></td></tr>`).join('') + '</tbody>';
  }
  $('#filtro').addEventListener('input', desenhaTabela);
  $('#filtro-faca').addEventListener('change', desenhaTabela);

  function montaFacas() {
    $('#tabela-facas').innerHTML = `<thead><tr><th>Faca</th><th>SKUs Siaga</th><th></th></tr></thead><tbody>` +
      D.facas.slice().sort((a, b) => a.nome.localeCompare(b.nome, 'pt', { numeric: true })).map(f => `<tr>
        <td>${esc(f.nome)}</td><td class="mono">${f.skus.map(esc).join(', ')}</td>
        <td style="white-space:nowrap"><button class="btn btn-ghost btn-sm" data-pdf="${f.id}" data-titulo="${esc(f.nome)}">Ver</button>
        <button class="btn btn-ghost btn-sm" data-baixar="${f.id}">Baixar</button>
        <button class="btn btn-ghost btn-sm" data-add="${esc(f.skus.join(','))}">+ Consulta</button></td></tr>`).join('') + '</tbody>';
  }

  // ---------------- sessão ----------------
  const k = store.get('cutdie.k');
  if (k) entra(b64d(k)).catch(() => { store.del('cutdie.k'); });
})();
