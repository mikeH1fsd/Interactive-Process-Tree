import { useState } from 'react';

export default function SplunkView() {
  const [inputText, setInputText] = useState('');
  const [pasteMode, setPasteMode] = useState('process');
  const [nodes, setNodes] = useState({});
  const [queryOutput, setQueryOutput] = useState(null);
  const [queryForm, setQueryForm] = useState({ name: '', pid: '' });
  
  const [config, setConfig] = useState({
    eventCodeField: 'EventCode',
    eventCodeValue: '1',
    parentImage: 'ParentImage',
    parentPid: 'ParentProcessId',
    image: 'Image',
    processId: 'ProcessId',
  });

  const handleConfigChange = (e) => {
    setConfig({ ...config, [e.target.name]: e.target.value });
  };

  const handleReset = () => {
    if (confirm("Bạn có chắc muốn xóa toàn bộ cây hiện tại để làm lại từ đầu không?")) {
      setNodes({});
      setInputText('');
      setQueryOutput(null);
    }
  };

  const handleParse = () => {
    if (!inputText.trim()) return;

    let normalizedText = inputText.trim();
    
    if (/Row:\s*\d+;\s*Column:\s*\d+/i.test(normalizedText)) {
      const lines = normalizedText.split('\n').map(l => l.trim()).filter(l => l !== '');
      const rowsMap = new Map();
      
      let currentValue = '';
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const match = line.match(/^Row:\s*(\d+);\s*Column:\s*(\d+)$/i);
        if (match) {
          const rowIdx = parseInt(match[1], 10);
          const colIdx = parseInt(match[2], 10);
          if (!rowsMap.has(rowIdx)) rowsMap.set(rowIdx, []);
          rowsMap.get(rowIdx)[colIdx - 1] = currentValue;
          currentValue = '';
        } else {
          currentValue = currentValue ? currentValue + ' ' + line : line;
        }
      }
      
      normalizedText = Array.from(rowsMap.entries())
        .sort((a, b) => a[0] - b[0])
        .map(([_, cols]) => cols.join('\t'))
        .join('\n');
    }

    const lines = normalizedText.split('\n');
    const currentNodes = JSON.parse(JSON.stringify(nodes));
    
    lines.forEach(line => {
      if (!line.trim()) return;
      
      let time, parentName, parentPid, processName, processPid, extraCols = '';

      let parts = line.split('\t');
      if (parts.length >= 5) {
        time = parts[0].trim();
        parentName = parts[1].trim();
        parentPid = parts[2].replace(/,/g, '').trim();
        processName = parts[3].trim();
        processPid = parts[4].replace(/,/g, '').trim();
        extraCols = parts.slice(5).join(' ');
      } else {
        parts = line.split(/\s{2,}/);
        if (parts.length >= 5) {
          time = parts[0].trim();
          parentName = parts[1].trim();
          parentPid = parts[2].replace(/,/g, '').trim();
          processName = parts[3].trim();
          processPid = parts[4].replace(/,/g, '').trim();
          extraCols = parts.slice(5).join(' ');
        } else {
          parts = line.trim().split(/\s+/);
          if (parts.length >= 4) {
            processPid = parts.pop().replace(/,/g, '').trim();
            processName = parts.pop().trim();
            parentPid = parts.pop().replace(/,/g, '').trim();
            parentName = parts.pop().trim();
            time = parts.join(' ');
          } else {
            return;
          }
        }
      }
      
      const parentId = `${parentName}_${parentPid}`;
      const processId = `${processName}_${processPid}`;
      
      if (!currentNodes[parentId]) {
        currentNodes[parentId] = { id: parentId, name: parentName, pid: parentPid, time: '', extra: '', children: [], parents: [], networkEvents: [], fileEvents: [], dnsEvents: [], regEvents: [] };
      }
      if (!currentNodes[processId]) {
        currentNodes[processId] = { id: processId, name: processName, pid: processPid, time: time, extra: extraCols, children: [], parents: [], networkEvents: [], fileEvents: [], dnsEvents: [], regEvents: [] };
      } else {
        if (time && !currentNodes[processId].time) {
            currentNodes[processId].time = time;
        }
        if (extraCols && !currentNodes[processId].extra) {
            currentNodes[processId].extra = extraCols;
        }
      }
      
      if (!currentNodes[parentId].children.includes(processId)) {
        currentNodes[parentId].children.push(processId);
      }
      if (!currentNodes[processId].parents.includes(parentId)) {
        currentNodes[processId].parents.push(parentId);
      }
    });

    setNodes(currentNodes);
    setInputText('');
  };

  const generateQueries = (pName, pid) => {
    if (!pid || !pName) return null;
    if (pid === '-' || pName === '-') return { splunk: "Invalid PID or Process Name" };

    const splunk = `${config.eventCodeField}="${config.eventCodeValue}" ((${config.processId}="${pid}" ${config.image}="${pName}") OR (${config.parentPid}="${pid}" ${config.parentImage}="${pName}")) | table _time, ${config.parentImage}, ${config.parentPid}, ${config.image}, ${config.processId}`;
    return { splunk };
  };

  const handleBulkExpand = () => {
    const nodeVals = Object.values(nodes);
    
    const rootNodes = [];
    const leafNodes = [];

    nodeVals.forEach(n => {
      if (n.pid !== '-' && n.name !== '-') {
        if (n.parents.length === 0) {
          rootNodes.push(n);
        } else if (n.children.length === 0) {
          leafNodes.push(n);
        }
      }
    });

    if (rootNodes.length === 0 && leafNodes.length === 0) return;

    const rootConditions = rootNodes.map(n => 
      `((${config.processId}="${n.pid}" ${config.image}="${n.name}") OR (${config.parentPid}="${n.pid}" ${config.parentImage}="${n.name}"))`
    );

    const leafConditions = leafNodes.map(n => 
      `(${config.parentPid}="${n.pid}" ${config.parentImage}="${n.name}")`
    );

    const allConditions = [...rootConditions, ...leafConditions];
    const splunk = `${config.eventCodeField}="${config.eventCodeValue}" (${allConditions.join(' OR ')}) | table _time, ${config.parentImage}, ${config.parentPid}, ${config.image}, ${config.processId}`;

    setQueryForm({ name: 'Boundary Nodes', pid: 'ALL' });
    setQueryOutput({ splunk });
  };

  const handleBulkRegistry = () => {
    const nodeVals = Object.values(nodes);
    const validNodes = nodeVals.filter(n => n.pid !== '-' && n.name !== '-');
    if (validNodes.length === 0) return;

    const uniqueNodes = [];
    const seen = new Set();
    validNodes.forEach(n => {
      const key = `${n.name}_${n.pid}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueNodes.push(n);
      }
    });

    const conditions = uniqueNodes.map(n => `(${config.processId}="${n.pid}" ${config.image}="${n.name}")`).join(' OR ');
    const splunk = `${config.eventCodeField}="13" (${conditions})`;
    
    setQueryForm({ name: 'All Nodes Registry', pid: 'ALL' });
    setQueryOutput({ splunk });
  };

  const handleGenerateAIPrompt = () => {
    const nodeVals = Object.values(nodes);
    if (nodeVals.length === 0) return;

    const roots = nodeVals.filter(n => n.parents.length === 0);
    if (roots.length === 0 && nodeVals.length > 0) {
      roots.push(nodeVals[0]);
    }

    roots.sort((a, b) => {
      const timeA = new Date(a.time?.replace('@', '') || 0).getTime() || 0;
      const timeB = new Date(b.time?.replace('@', '') || 0).getTime() || 0;
      return timeA - timeB;
    });

    let treeText = '';

    const buildTextNode = (nodeId, prefix, isLast, visited, isRoot = false) => {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      
      const node = nodes[nodeId];
      if (!node) return;
      
      let linePrefix = prefix;
      if (!isRoot) linePrefix += isLast ? '└── ' : '├── ';
      
      treeText += `${linePrefix}${node.name} (PID: ${node.pid}) ${node.time ? `[Time: ${node.time}]` : ''} ${node.extra ? `[Extra: ${node.extra}]` : ''}\n`;
      
      let childPrefix = prefix;
      if (!isRoot) childPrefix += isLast ? '    ' : '│   ';

      if (node.fileEvents && node.fileEvents.length > 0) {
        node.fileEvents.forEach((file, idx) => {
          const isFileLast = (idx === node.fileEvents.length - 1) && (!node.dnsEvents || node.dnsEvents.length === 0) && (!node.regEvents || node.regEvents.length === 0) && (!node.networkEvents || node.networkEvents.length === 0) && node.children.length === 0;
          const filePrefix = childPrefix + (isFileLast ? '└── ' : '├── ');
          treeText += `${filePrefix}[FILE] ${file.filePath} ${file.timestamp ? `[Time: ${file.timestamp}]` : ''} ${file.extra ? `[Extra: ${file.extra}]` : ''}\n`;
        });
      }

      if (node.dnsEvents && node.dnsEvents.length > 0) {
        node.dnsEvents.forEach((dns, idx) => {
          const isDnsLast = (idx === node.dnsEvents.length - 1) && (!node.regEvents || node.regEvents.length === 0) && (!node.networkEvents || node.networkEvents.length === 0) && node.children.length === 0;
          const dnsPrefix = childPrefix + (isDnsLast ? '└── ' : '├── ');
          treeText += `${dnsPrefix}[DNS] ${dns.dnsQuestion} -> ${dns.dnsIp} ${dns.extra ? `[Extra: ${dns.extra}]` : ''}\n`;
        });
      }

      if (node.regEvents && node.regEvents.length > 0) {
        node.regEvents.forEach((reg, idx) => {
          const isRegLast = (idx === node.regEvents.length - 1) && (!node.networkEvents || node.networkEvents.length === 0) && node.children.length === 0;
          const regPrefix = childPrefix + (isRegLast ? '└── ' : '├── ');
          treeText += `${regPrefix}[REGISTRY] ${reg.regPath} = ${reg.regData} ${reg.timestamp ? `[Time: ${reg.timestamp}]` : ''} ${reg.extra ? `[Extra: ${reg.extra}]` : ''}\n`;
        });
      }

      if (node.networkEvents && node.networkEvents.length > 0) {
        node.networkEvents.forEach((net, idx) => {
          const isNetLast = (idx === node.networkEvents.length - 1) && node.children.length === 0;
          const netPrefix = childPrefix + (isNetLast ? '└── ' : '├── ');
          treeText += `${netPrefix}[NETWORK] ${net.srcIp} -> ${net.destIp} ${net.extra ? `[Extra: ${net.extra}]` : ''}\n`;
        });
      }

      const childrenIds = [...node.children].filter(id => nodes[id]);
      childrenIds.sort((idA, idB) => {
        const timeA = new Date(nodes[idA]?.time?.replace('@', '') || 0).getTime() || 0;
        const timeB = new Date(nodes[idB]?.time?.replace('@', '') || 0).getTime() || 0;
        return timeA - timeB;
      });

      childrenIds.forEach((childId, index) => {
        const isChildLast = index === childrenIds.length - 1;
        buildTextNode(childId, childPrefix, isChildLast, new Set(visited), false);
      });
    };

    roots.forEach((root, index) => {
      buildTextNode(root.id, '', index === roots.length - 1, new Set(), true);
      if (index < roots.length - 1) treeText += '\n';
    });

    const prompt = `As a cybersecurity expert and threat hunter, please analyze the following process execution tree. 
This tree may contain process spawn events, network connections [NETWORK], DNS queries [DNS], file creations [FILE], and registry modifications [REGISTRY].

Are there any suspicious behaviors, anomalies, or potential indicators of compromise (IoC) here? 
If so, please explain what is unusual and outline what the attacker might be trying to achieve.

Process Tree Data:
${treeText}`;

    setQueryForm({ name: 'AI Analysis', pid: 'PROMPT' });
    setQueryOutput({ aiPrompt: prompt });
  };

  const handleDeleteBranch = (nodeId) => {
    if (!confirm("Bạn có chắc muốn xoá nhánh này (bao gồm cả các tiến trình con)?")) return;

    const currentNodes = JSON.parse(JSON.stringify(nodes));

    const idsToDelete = new Set();
    const gatherChildren = (id) => {
      if (!currentNodes[id] || idsToDelete.has(id)) return;
      idsToDelete.add(id);
      currentNodes[id].children.forEach(childId => gatherChildren(childId));
    };
    gatherChildren(nodeId);

    idsToDelete.forEach(id => {
      const nodeToDelete = currentNodes[id];
      if (nodeToDelete) {
        nodeToDelete.parents.forEach(parentId => {
          if (currentNodes[parentId] && !idsToDelete.has(parentId)) {
            currentNodes[parentId].children = currentNodes[parentId].children.filter(childId => childId !== id);
          }
        });
      }
      delete currentNodes[id];
    });

    setNodes(currentNodes);
  };

  const handleGenerateQueryForm = (e) => {
    e.preventDefault();
    const result = generateQueries(queryForm.name, queryForm.pid);
    if (result) setQueryOutput(result);
  };

  const handleNodeClick = (node) => {
    setQueryForm({ name: node.name, pid: node.pid });
    const result = generateQueries(node.name, node.pid);
    if (result) setQueryOutput(result);
  };

  const renderTree = () => {
    const nodeVals = Object.values(nodes);
    if (nodeVals.length === 0) return 'Chưa có dữ liệu...';
    
    const roots = nodeVals.filter(n => n.parents.length === 0);
    if (roots.length === 0 && nodeVals.length > 0) {
      roots.push(nodeVals[0]);
    }

    roots.sort((a, b) => {
      const timeA = new Date(a.time?.replace('@', '') || 0).getTime() || 0;
      const timeB = new Date(b.time?.replace('@', '') || 0).getTime() || 0;
      return timeA - timeB;
    });

    const elements = [];
    
    const buildNode = (nodeId, prefix, isLast, visited, isRoot = false) => {
      if (visited.has(nodeId)) return;
      visited.add(nodeId);
      
      const node = nodes[nodeId];
      if (!node) return;
      
      let linePrefix = prefix;
      if (!isRoot) {
        linePrefix += isLast ? '└── ' : '├── ';
      }
      
      elements.push(
        <div key={`${nodeId}-${elements.length}`} className="tree-line">
          <span className="tree-prefix">{linePrefix}</span>
          <span className="tree-node-text process">🟢 {node.name} {node.time ? `[${node.time}]` : ''} (PID {node.pid})</span>
          {node.extra && <span className="tree-extra">[{node.extra}]</span>}
          <div className="node-actions">
            <button className="action-btn" onClick={() => handleNodeClick(node)} title="Sinh Query cho Process này">🔍</button>
            <button className="action-btn delete" onClick={() => handleDeleteBranch(nodeId)} title="Xoá nhánh này">🗑️</button>
          </div>
        </div>
      );
      
      let childPrefix = prefix;
      if (!isRoot) {
        childPrefix += isLast ? '    ' : '│   ';
      }

      if (node.fileEvents && node.fileEvents.length > 0) {
        node.fileEvents.forEach((file, idx) => {
          const isFileLast = (idx === node.fileEvents.length - 1) && (!node.dnsEvents || node.dnsEvents.length === 0) && (!node.regEvents || node.regEvents.length === 0) && (!node.networkEvents || node.networkEvents.length === 0) && node.children.length === 0;
          const filePrefix = childPrefix + (isFileLast ? '└── ' : '├── ');
          elements.push(
            <div key={`${nodeId}-file-${idx}`} className="tree-line">
              <span className="tree-prefix">{filePrefix}</span>
              <span className="tree-node-text file">📄 {file.filePath} {file.timestamp ? `[${file.timestamp}]` : ''}</span>
              {file.extra && <span className="tree-extra">[{file.extra}]</span>}
            </div>
          );
        });
      }

      if (node.dnsEvents && node.dnsEvents.length > 0) {
        node.dnsEvents.forEach((dns, idx) => {
          const isDnsLast = (idx === node.dnsEvents.length - 1) && (!node.regEvents || node.regEvents.length === 0) && (!node.networkEvents || node.networkEvents.length === 0) && node.children.length === 0;
          const dnsPrefix = childPrefix + (isDnsLast ? '└── ' : '├── ');
          elements.push(
            <div key={`${nodeId}-dns-${idx}`} className="tree-line">
              <span className="tree-prefix">{dnsPrefix}</span>
              <span className="tree-node-text dns">📡 {dns.dnsQuestion} {"->"} {dns.dnsIp}</span>
              {dns.extra && <span className="tree-extra">[{dns.extra}]</span>}
            </div>
          );
        });
      }

      if (node.regEvents && node.regEvents.length > 0) {
        node.regEvents.forEach((reg, idx) => {
          const isRegLast = (idx === node.regEvents.length - 1) && (!node.networkEvents || node.networkEvents.length === 0) && node.children.length === 0;
          const regPrefix = childPrefix + (isRegLast ? '└── ' : '├── ');
          elements.push(
            <div key={`${nodeId}-reg-${idx}`} className="tree-line">
              <span className="tree-prefix">{regPrefix}</span>
              <span className="tree-node-text registry">🗄️ {reg.regPath} = {reg.regData} {reg.timestamp ? `[${reg.timestamp}]` : ''}</span>
              {reg.extra && <span className="tree-extra">[{reg.extra}]</span>}
            </div>
          );
        });
      }

      const childrenIds = [...node.children].filter(id => nodes[id]);
      childrenIds.sort((idA, idB) => {
        const timeA = new Date(nodes[idA]?.time?.replace('@', '') || 0).getTime() || 0;
        const timeB = new Date(nodes[idB]?.time?.replace('@', '') || 0).getTime() || 0;
        return timeA - timeB;
      });

      childrenIds.forEach((childId, index) => {
        const isChildLast = index === childrenIds.length - 1;
        buildNode(childId, childPrefix, isChildLast, new Set(visited), false);
      });
    };

    roots.forEach((root, index) => {
      buildNode(root.id, '', index === roots.length - 1, new Set(), true);
      if (index < roots.length - 1) {
        elements.push(<div key={`spacer-${index}`} className="tree-line"><br/></div>);
      }
    });

    return elements;
  };

  return (
    <main className="layout">
      <aside className="sidebar">
        <section className="card">
          <h2>1. Cấu hình Field Name</h2>
          <div className="input-group">
            <label>Event Code Field:</label>
            <input name="eventCodeField" value={config.eventCodeField} onChange={handleConfigChange} />
          </div>
          <div className="input-group">
            <label>Event Code Value:</label>
            <input name="eventCodeValue" value={config.eventCodeValue} onChange={handleConfigChange} />
          </div>
          <div className="input-group">
            <label>Parent Image Field:</label>
            <input name="parentImage" value={config.parentImage} onChange={handleConfigChange} />
          </div>
          <div className="input-group">
            <label>Parent PID Field:</label>
            <input name="parentPid" value={config.parentPid} onChange={handleConfigChange} />
          </div>
          <div className="input-group">
            <label>Process Image Field:</label>
            <input name="image" value={config.image} onChange={handleConfigChange} />
          </div>
          <div className="input-group">
            <label>Process PID Field:</label>
            <input name="processId" value={config.processId} onChange={handleConfigChange} />
          </div>
        </section>

        <section className="card sticky-card">
          <h2>2. Sinh Query Tìm Kiếm</h2>
          <form onSubmit={handleGenerateQueryForm}>
            <div className="input-group">
              <label>Mode:</label>
              <div className="paste-modes">
                <label className={`paste-mode-label ${pasteMode === 'process' ? 'active' : ''}`}>
                  <input type="radio" name="pasteMode" value="process" checked={pasteMode === 'process'} onChange={(e) => setPasteMode(e.target.value)} />
                  Process (Event 1)
                </label>
                <label className={`paste-mode-label ${pasteMode === 'dns' ? 'active' : ''}`}>
                  <input type="radio" name="pasteMode" value="dns" checked={pasteMode === 'dns'} onChange={(e) => setPasteMode(e.target.value)} />
                  DNS (Event 22)
                </label>
                <label className={`paste-mode-label ${pasteMode === 'file' ? 'active' : ''}`}>
                  <input type="radio" name="pasteMode" value="file" checked={pasteMode === 'file'} onChange={(e) => setPasteMode(e.target.value)} />
                  File (Event 11)
                </label>
                <label className={`paste-mode-label ${pasteMode === 'registry' ? 'active' : ''}`}>
                  <input type="radio" name="pasteMode" value="registry" checked={pasteMode === 'registry'} onChange={(e) => setPasteMode(e.target.value)} />
                  Registry (Event 13)
                </label>
              </div>
            </div>
            <div className="input-group">
              <label>Process Name:</label>
              <input 
                value={queryForm.name} 
                onChange={e => setQueryForm({...queryForm, name: e.target.value})} 
                placeholder="Ví dụ: cmd.exe" 
                required 
              />
            </div>
            <div className="input-group">
              <label>Process PID:</label>
              <input 
                value={queryForm.pid} 
                onChange={e => setQueryForm({...queryForm, pid: e.target.value})} 
                placeholder="Ví dụ: 1200" 
                required 
              />
            </div>
            <button type="submit">Sinh Query Đơn</button>
          </form>
          <div className="action-buttons">
            <button type="button" onClick={handleBulkExpand} className="btn-expand" title="Tự động gom tất cả Root (gốc) và Leaf (ngọn) để truy vấn mở rộng biên của cây">🔍 Bulk Expand Tree</button>
            <button type="button" onClick={handleGenerateAIPrompt} title="Sinh prompt chứa toàn bộ dữ liệu cây để nhờ AI (ChatGPT/Gemini) phân tích">🤖 Generate AI Prompt</button>
            <button type="button" onClick={handleBulkRegistry} className="btn-registry" title="Tạo Query tìm Registry Change (Event 13) cho tất cả Process hiện có">🗄️ Query Registry</button>
          </div>
          {queryOutput && (
            <div className="output-box">
              {queryOutput.splunk && (
                <>
                  <strong>Splunk Query:</strong>
                  <textarea readOnly value={queryOutput.splunk} rows={4} onClick={e => e.target.select()} />
                </>
              )}
              {queryOutput.aiPrompt && (
                <>
                  <strong>AI Analysis Prompt (Copy & Paste to ChatGPT/Gemini):</strong>
                  <textarea readOnly value={queryOutput.aiPrompt} rows={12} onClick={e => e.target.select()} />
                </>
              )}
            </div>
          )}
        </section>
      </aside>

      <section className="main-content">
        <div className="card full-height">
          <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
             <h2>3. Thêm Nhánh Mới vào Cây</h2>
             <button onClick={handleReset} style={{width: 'auto', backgroundColor: '#da3633', padding: '5px 15px', fontSize: '0.9rem'}}>Xóa toàn bộ cây (Reset)</button>
          </div>
          <p className="hint-text">Cứ mỗi lần chạy được kết quả mới, bạn Paste đè vào đây. Tool sẽ tự động ghép nhánh mới vào cây cũ và làm rỗng ô nhập liệu.</p>
          <textarea 
            placeholder="Paste kết quả Query mới vào đây..." 
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            rows={6}
          />
          <button onClick={handleParse} className="build-btn">Ghép vào Process Tree</button>
          
          <div className="tree-container">
            <h3>Cây Tiến Trình Hiện Tại:</h3>
            <div className="ascii-tree">
              {renderTree()}
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
