import { useState } from 'react';
import './App.css';

function App() {
  const [inputText, setInputText] = useState('');
  // Use a persistent state for nodes so we can append iteratively
  const [nodes, setNodes] = useState({});
  const [queryOutput, setQueryOutput] = useState(null);
  const [queryForm, setQueryForm] = useState({ name: '', pid: '' });
  
  // Query config state
  const [config, setConfig] = useState({
    eventCodeField: 'event.code',
    eventCodeValue: '1',
    parentImage: 'process.parent.name',
    parentPid: 'process.parent.pid',
    image: 'process.name',
    processId: 'process.pid',
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
    
    // Auto-detect and convert vertical "Row: X; Column: Y" format to TSV
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
    // Deep clone existing nodes to maintain state immutability
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
        currentNodes[parentId] = { id: parentId, name: parentName, pid: parentPid, time: '', extra: '', children: [], parents: [] };
      }
      if (!currentNodes[processId]) {
        currentNodes[processId] = { id: processId, name: processName, pid: processPid, time: time, extra: extraCols, children: [], parents: [] };
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
    // Xóa textarea đi cho người dùng dán cái mới
    setInputText('');
  };

  const generateQueries = (pName, pid) => {
    if (!pid || !pName) return null;
    
    if (pid === '-' || pName === '-') {
       return { splunk: "Invalid PID or Process Name", elastic: "Invalid PID or Process Name" };
    }

    const splunk = `${config.eventCodeField}="${config.eventCodeValue}" ((${config.processId}="${pid}" ${config.image}="${pName}") OR (${config.parentPid}="${pid}" ${config.parentImage}="${pName}")) | table _time, ${config.parentImage}, ${config.parentPid}, ${config.image}, ${config.processId}`;
    const elastic = `${config.eventCodeField}:"${config.eventCodeValue}" and ((${config.processId}:"${pid}" and ${config.image}:"${pName}") or (${config.parentPid}:"${pid}" and ${config.parentImage}:"${pName}"))`;
    
    return { splunk, elastic };
  };

  const generateBulkQueries = (nodesList) => {
    if (!nodesList || nodesList.length === 0) return null;
    const validNodes = nodesList.filter(n => n.pid !== '-' && n.name !== '-');
    if (validNodes.length === 0) return { splunk: "No valid nodes", elastic: "No valid nodes" };

    const splunkConditions = validNodes.map(n => 
      `((${config.processId}="${n.pid}" ${config.image}="${n.name}") OR (${config.parentPid}="${n.pid}" ${config.parentImage}="${n.name}"))`
    ).join(' OR ');

    const elasticConditions = validNodes.map(n => 
      `((${config.processId}:"${n.pid}" and ${config.image}:"${n.name}") or (${config.parentPid}:"${n.pid}" and ${config.parentImage}:"${n.name}"))`
    ).join(' or ');

    const splunk = `${config.eventCodeField}="${config.eventCodeValue}" (${splunkConditions}) | table _time, ${config.parentImage}, ${config.parentPid}, ${config.image}, ${config.processId}`;
    const elastic = `${config.eventCodeField}:"${config.eventCodeValue}" and (${elasticConditions})`;
    return { splunk, elastic };
  };

  const handleBulkExpand = () => {
    const nodeVals = Object.values(nodes);
    const boundaryNodes = new Map();
    
    nodeVals.forEach(n => {
      if (n.children.length === 0 || n.parents.length === 0) {
        boundaryNodes.set(n.id, n);
      }
    });

    const list = Array.from(boundaryNodes.values());
    const result = generateBulkQueries(list);
    if (result) {
       setQueryForm({ name: 'Boundary Nodes', pid: 'ALL' });
       setQueryOutput(result);
    }
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
    // Xử lý vòng lặp nếu có (circular dependencies) hoặc dữ liệu mồ côi
    if (roots.length === 0 && nodeVals.length > 0) {
      roots.push(nodeVals[0]);
    }

    // Sort roots by time
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
          <span className="tree-node-text">{node.name} {node.time ? `[${node.time}]` : ''} (PID {node.pid})</span>
          {node.extra && <span className="tree-extra">[{node.extra}]</span>}
          <button 
            className="action-btn" 
            onClick={() => handleNodeClick(node)}
            title="Sinh Query cho Process này"
          >
            🔍 Query
          </button>
        </div>
      );
      
      let childPrefix = prefix;
      if (!isRoot) {
        childPrefix += isLast ? '    ' : '│   ';
      }
      
      const childrenIds = [...node.children];
      childrenIds.sort((idA, idB) => {
        const timeA = new Date(nodes[idA].time?.replace('@', '') || 0).getTime() || 0;
        const timeB = new Date(nodes[idB].time?.replace('@', '') || 0).getTime() || 0;
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
    <div className="container">
      <header>
        <h1>Interactive Process Tree Builder</h1>
        <p>Giao diện Full Screen - Mở Rộng Nhánh Liên Tục</p>
      </header>
      
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
            <div style={{marginTop: '10px'}}>
              <button type="button" onClick={handleBulkExpand} style={{backgroundColor: '#1f6feb', fontSize: '0.9rem'}} title="Tự động gom tất cả Root (gốc) và Leaf (ngọn) để truy vấn mở rộng biên của cây">🔍 Bulk Expand Tree (Gộp Roots & Leaves)</button>
            </div>
            {queryOutput && (
              <div className="output-box">
                <strong>Splunk Query:</strong>
                <textarea readOnly value={queryOutput.splunk} rows={3} style={{marginBottom: '10px'}} onClick={e => e.target.select()} />
                <strong>Elastic (KQL) Query:</strong>
                <textarea readOnly value={queryOutput.elastic} rows={3} onClick={e => e.target.select()} />
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
    </div>
  );
}

export default App;
