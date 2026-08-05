import { useState, useRef, useEffect } from 'react';
import ElasticView from './components/ElasticView';
import SplunkView from './components/SplunkView';
import ElasticApiView from './components/ElasticApiView';
import SplunkApiView from './components/SplunkApiView';
import PatternLibrary from './components/PatternLibrary';
import './App.css';
import JSZip from 'jszip';
import { saveAs } from 'file-saver';

const useSessionStorage = (key, initialValue) => {
  const [value, setValue] = useState(() => {
    try {
      const item = window.sessionStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      return initialValue;
    }
  });
  useEffect(() => {
    try {
      window.sessionStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.warn("sessionStorage limit exceeded");
    }
  }, [key, value]);
  return [value, setValue];
};

function App() {
  const [platform, setPlatform] = useSessionStorage('app_platform', 'elastic');
  const [isPatternLibraryOpen, setIsPatternLibraryOpen] = useState(false);
  const fileInputRef = useRef(null);

  
  const handleExportToAI = () => {
    let folderName = window.prompt("Nhập tên Folder để Export cho AI (để trống sẽ lấy thời gian hiện tại):");
    if (folderName === null) return;
    
    if (!folderName.trim()) {
      const now = new Date();
      const pad = (n) => n.toString().padStart(2, '0');
      folderName = `AI_Export_${now.getFullYear()}${pad(now.getMonth()+1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
    }

    const zip = new JSZip();

    const promptText = `Bạn là một chuyên gia phân tích an toàn thông tin (SOC Tier 3 / Threat Hunter).
Tui đang cung cấp cho bạn một tập hợp các Process Tree (Cây tiến trình) được kết xuất từ hệ thống trong quá trình điều tra sự cố.
Mỗi file text đi kèm đại diện cho một nhánh điều tra (Workspace).
Cấu trúc dữ liệu đã được tối ưu hóa thành định dạng danh sách lồng nhau (Nested List). Các dòng thụt lề biểu thị mối quan hệ cha-con giữa các tiến trình. Mỗi tiến trình có đính kèm các sự kiện liên quan (Network, File, DNS, Registry, PowerShell).

NHIỆM VỤ CỦA BẠN:
1. Phân tích ngữ cảnh (Context) của từng cây tiến trình. Xác định xem hành vi này là bình thường (Benign) hay độc hại (Malicious).
2. Chỉ ra các điểm bất thường (Anomalies): ví dụ tiến trình hợp lệ nhưng đẻ ra từ thư mục lạ, kết nối mạng đến IP đáng ngờ, hoặc chạy PowerShell với tham số bị mã hóa (Base64).
3. Mapping các hành vi tìm thấy vào MITRE ATT&CK Framework.
4. Tóm tắt nhanh chuỗi tấn công (Kill Chain) nếu có.

Hãy đọc kỹ từng file, tập hợp thông tin và cho tôi biết nhận định của bạn.`;

    zip.file("prompt_engineer.txt", promptText);

    let prefix = 'elastic_manual_';
    if (platform === 'elastic') prefix = 'elastic_manual_';
    else if (platform === 'splunk') prefix = 'splunk_manual_';
    else if (platform === 'elastic_api') prefix = 'elastic_api_';
    else if (platform === 'splunk_api') prefix = 'splunk_api_';

    const workspacesStr = window.sessionStorage.getItem(prefix + 'workspaces');
    const workspaceDataStr = window.sessionStorage.getItem(prefix + 'workspaceData');

    if (workspacesStr && workspaceDataStr) {
      const workspaces = JSON.parse(workspacesStr);
      const workspaceData = JSON.parse(workspaceDataStr);

      const buildMarkdownTree = (nodesObj, rootId, depth = 0) => {
        let md = '';
        const node = nodesObj[rootId];
        if (!node) return md;

        const indent = '  '.repeat(depth);
        md += `${indent}- **[Process]** \`${node.name}\` (PID: ${node.pid}) | Guid: ${node.id}\n`;
        if (node.time) md += `${indent}  - **[Time]** ${node.time}\n`;
        if (node.extra) md += `${indent}  - **[Info]** ${node.extra}\n`;

        if (node.networkEvents && node.networkEvents.length > 0) {
          md += `${indent}  - **[Network Events]**:\n`;
          node.networkEvents.forEach(e => {
            md += `${indent}    - ${e.extraStr} | Count: ${e.count} | FirstTime: ${e.firstTime} | LastTime: ${e.lastTime}\n`;
          });
        }
        
        if (node.fileEvents && node.fileEvents.length > 0) {
          md += `${indent}  - **[File Events]**:\n`;
          node.fileEvents.forEach(e => {
            md += `${indent}    - ${e.extraStr} | Count: ${e.count} | FirstTime: ${e.firstTime} | LastTime: ${e.lastTime}\n`;
          });
        }

        if (node.dnsEvents && node.dnsEvents.length > 0) {
          md += `${indent}  - **[DNS Events]**:\n`;
          node.dnsEvents.forEach(e => {
            md += `${indent}    - ${e.extraStr} | Count: ${e.count} | FirstTime: ${e.firstTime} | LastTime: ${e.lastTime}\n`;
          });
        }

        if (node.regEvents && node.regEvents.length > 0) {
          md += `${indent}  - **[Registry Events]**:\n`;
          node.regEvents.forEach(e => {
            md += `${indent}    - ${e.extraStr} | Count: ${e.count} | FirstTime: ${e.firstTime} | LastTime: ${e.lastTime}\n`;
          });
        }

        if (node.psEvents && node.psEvents.length > 0) {
          md += `${indent}  - **[PowerShell Scripts]**:\n`;
          node.psEvents.forEach(e => {
            md += `${indent}    - ${e.extraStr} | Count: ${e.count} | FirstTime: ${e.firstTime} | LastTime: ${e.lastTime}\n`;
          });
        }

        if (node.children && node.children.length > 0) {
          md += `${indent}  - **[Children]**:\n`;
          const sortedChildren = [...node.children].sort((a, b) => {
             const tA = nodesObj[a]?.time || '';
             const tB = nodesObj[b]?.time || '';
             return tA.localeCompare(tB);
          });
          sortedChildren.forEach(childId => {
            md += buildMarkdownTree(nodesObj, childId, depth + 2);
          });
        }

        return md;
      };

      workspaces.forEach(ws => {
        const nodesObj = workspaceData[ws.id];
        if (!nodesObj || Object.keys(nodesObj).length === 0) return;

        const roots = Object.values(nodesObj).filter(n => !n.parents || n.parents.length === 0);
        let wsMd = `# Workspace: ${ws.name}\n\n## Process Hierarchy\n\n`;
        roots.forEach(r => {
          wsMd += buildMarkdownTree(nodesObj, r.id, 0);
        });

        const safeFileName = ws.name.replace(/[^a-z0-9]/gi, '_').toLowerCase();
        zip.file(`tree_${safeFileName}.md`, wsMd);
      });
    }

    zip.generateAsync({ type: "blob" }).then(function(content) {
        saveAs(content, folderName + ".zip");
    });
  };

  const handleExport = () => {
    const sessionData = {};
    for (let i = 0; i < window.sessionStorage.length; i++) {
      const key = window.sessionStorage.key(i);
      sessionData[key] = window.sessionStorage.getItem(key);
    }
    const jsonString = JSON.stringify(sessionData, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    let filename = window.prompt("Nhập tên file để lưu (để trống sẽ tự động lấy thời gian hiện tại):");
    if (filename === null) return; // User cancelled
    
    if (!filename.trim()) {
      const now = new Date();
      const pad = (n) => n.toString().padStart(2, '0');
      filename = `session_${now.getFullYear()}${pad(now.getMonth()+1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}.json`;
    } else if (!filename.endsWith('.json')) {
      filename += '.json';
    }

    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleImport = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const sessionData = JSON.parse(event.target.result);
        window.sessionStorage.clear();
        for (const [key, value] of Object.entries(sessionData)) {
          window.sessionStorage.setItem(key, value);
        }
        window.location.reload();
      } catch (error) {
        alert("File không hợp lệ hoặc bị lỗi!");
        console.error("Error importing session:", error);
      }
    };
    reader.readAsText(file);
    e.target.value = ''; // Reset input
  };

  return (
    <div className="container">
      <header className="app-header">
        <div className="title-group">
          <h1>Threat Hunt Builder</h1>
        </div>
        
        <div className="platform-selector" style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <button 
            onClick={() => setIsPatternLibraryOpen(true)}
            style={{ padding: '8px 15px', backgroundColor: 'rgba(59, 130, 246, 0.1)', color: '#60a5fa', border: '1px solid rgba(59, 130, 246, 0.3)', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '5px', transition: 'all 0.2s' }}
            onMouseOver={(e) => { e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.2)'; }}
            onMouseOut={(e) => { e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.1)'; }}
          >
            <span>📚</span> Thư viện Patterns
          </button>

          <button 
            onClick={handleExportToAI}
            style={{ padding: '8px 15px', backgroundColor: 'rgba(139, 92, 246, 0.1)', color: '#8b5cf6', border: '1px solid rgba(139, 92, 246, 0.3)', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '5px', transition: 'all 0.2s', marginLeft: '5px' }}
            onMouseOver={(e) => { e.currentTarget.style.backgroundColor = 'rgba(139, 92, 246, 0.2)'; }}
            onMouseOut={(e) => { e.currentTarget.style.backgroundColor = 'rgba(139, 92, 246, 0.1)'; }}
            title="Đóng gói Process Tree xuất cho AI phân tích"
          >
            <span>🤖</span> Export cho AI
          </button>

          <button 
            onClick={handleExport}
            style={{ padding: '8px 15px', backgroundColor: 'rgba(16, 185, 129, 0.1)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '5px', transition: 'all 0.2s', marginLeft: '5px' }}
            onMouseOver={(e) => { e.currentTarget.style.backgroundColor = 'rgba(16, 185, 129, 0.2)'; }}
            onMouseOut={(e) => { e.currentTarget.style.backgroundColor = 'rgba(16, 185, 129, 0.1)'; }}
            title="Lưu toàn bộ phiên làm việc hiện tại"
          >
            <span>💾</span> Export Session
          </button>

          <button 
            onClick={() => fileInputRef.current.click()}
            style={{ padding: '8px 15px', backgroundColor: 'rgba(245, 158, 11, 0.1)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '5px', transition: 'all 0.2s', marginLeft: '5px' }}
            onMouseOver={(e) => { e.currentTarget.style.backgroundColor = 'rgba(245, 158, 11, 0.2)'; }}
            onMouseOut={(e) => { e.currentTarget.style.backgroundColor = 'rgba(245, 158, 11, 0.1)'; }}
            title="Khôi phục phiên làm việc từ file đã lưu"
          >
            <span>📂</span> Import Session
          </button>
          <input 
            type="file" 
            accept=".json" 
            ref={fileInputRef} 
            style={{ display: 'none' }} 
            onChange={handleImport}
          />
          
          <div style={{ display: 'flex', gap: '10px', marginLeft: '10px' }}>
            <label className={platform === 'elastic' ? 'active' : ''}>
              <input type="radio" name="platform" value="elastic" checked={platform === 'elastic'} onChange={(e) => setPlatform(e.target.value)} />
              Elastic (Copy/Paste)
            </label>
            <label className={platform === 'elastic_api' ? 'active' : ''}>
              <input type="radio" name="platform" value="elastic_api" checked={platform === 'elastic_api'} onChange={(e) => setPlatform(e.target.value)} />
              Elastic API
            </label>
            <label className={platform === 'splunk' ? 'active' : ''}>
              <input type="radio" name="platform" value="splunk" checked={platform === 'splunk'} onChange={(e) => setPlatform(e.target.value)} />
              Splunk (Copy/Paste)
            </label>
            <label className={platform === 'splunk_api' ? 'active' : ''}>
              <input type="radio" name="platform" value="splunk_api" checked={platform === 'splunk_api'} onChange={(e) => setPlatform(e.target.value)} />
              Splunk API
            </label>
          </div>
        </div>
      </header>

      <div style={{ display: platform === 'elastic' ? 'block' : 'none' }}>
        <ElasticApiView isManualMode={true} />
      </div>
      <div style={{ display: platform === 'splunk' ? 'block' : 'none' }}>
        <SplunkApiView isManualMode={true} />
      </div>
      <div style={{ display: platform === 'elastic_api' ? 'block' : 'none' }}>
        <ElasticApiView />
      </div>
      <div style={{ display: platform === 'splunk_api' ? 'block' : 'none' }}>
        <SplunkApiView />
      </div>

      <PatternLibrary 
        isOpen={isPatternLibraryOpen} 
        onClose={() => setIsPatternLibraryOpen(false)}
        currentPlatform={platform}
      />
    </div>
  );
}

export default App;
