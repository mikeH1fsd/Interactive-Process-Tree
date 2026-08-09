import React, { useState, useEffect, useRef } from 'react';
import AutocompleteInput from './AutocompleteInput';

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

function SplunkApiView({ isManualMode = false }) {
  const storagePrefix = isManualMode ? 'splunk_manual_' : 'splunk_api_';
  const escapeSplunk = (str) => (str || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');

  const [apiUrl, setApiUrl] = useSessionStorage(storagePrefix + 'apiUrl', 'http://10.48.144.79:9200');
  const [username, setUsername] = useSessionStorage(storagePrefix + 'username', 'elastic');
  const [password, setPassword] = useSessionStorage(storagePrefix + 'password', 'elastic');
  const [indexPattern, setIndexPattern] = useSessionStorage(storagePrefix + 'indexPattern', 'winlogbeat-*');

  // Fields Mapping
  const [eventCodeField, setEventCodeField] = useSessionStorage(storagePrefix + 'eventCodeField', 'EventCode');
  const [parentNameField, setParentNameField] = useSessionStorage(storagePrefix + 'parentNameField', 'ParentImage');
  const [parentPidField, setParentPidField] = useSessionStorage(storagePrefix + 'parentPidField', 'ParentProcessId');
  const [processNameField, setProcessNameField] = useSessionStorage(storagePrefix + 'processNameField', 'Image');
  const [processPidField, setProcessPidField] = useSessionStorage(storagePrefix + 'processPidField', 'ProcessId');
  const [parentGuidField, setParentGuidField] = useSessionStorage(storagePrefix + 'parentGuidField', 'ParentProcessGuid');
  const [processGuidField, setProcessGuidField] = useSessionStorage(storagePrefix + 'processGuidField', 'ProcessGuid');

  // Search
  const [searchProcessName, setSearchProcessName] = useState('');
  const [searchProcessPid, setSearchProcessPid] = useState('');

  // Manual Mode State
  const [manualRequest, setManualRequest] = useState(null);
  const [manualResponseInput, setManualResponseInput] = useState('');
  
  // Custom fetch wrapper
  const executeQuery = async (endpoint, options) => {
    if (isManualMode) {
      if (options.method !== 'POST' || !options.body) {
        return { ok: true, json: () => Promise.resolve([]) };
      }
      return new Promise((resolve, reject) => {
        setManualRequest({
          endpoint,
          query: options.body,
          onResolve: (jsonResponse) => {
            setManualRequest(null);
            resolve({ ok: true, json: () => Promise.resolve(jsonResponse) });
          },
          onReject: (err) => {
            setManualRequest(null);
            reject(err);
          }
        });
      });
    } else {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 60000);
        const res = await fetch(endpoint, { ...options, signal: controller.signal });
        clearTimeout(timeoutId);
        return res;
      } catch (err) {
        if (err.name === 'AbortError') {
          throw new Error('Request Timeout (60s)');
        }
        throw err;
      }
    }
  };

  // Event 3 Config
  const [evt3CodeField, setEvt3CodeField] = useSessionStorage(storagePrefix + 'evt3CodeField', 'EventCode');
  const [evt3CodeValue, setEvt3CodeValue] = useSessionStorage(storagePrefix + 'evt3CodeValue', '3');
  const [evt3ProcessNameField, setEvt3ProcessNameField] = useSessionStorage(storagePrefix + 'evt3ProcessNameField', 'Image');
  const [evt3ProcessPidField, setEvt3ProcessPidField] = useSessionStorage(storagePrefix + 'evt3ProcessPidField', 'ProcessId');
  const [evt3ExtraField, setEvt3ExtraField] = useSessionStorage(storagePrefix + 'evt3ExtraField', 'DestinationIp, DestinationPort');

  // Event 11 Config
  const [evt11CodeField, setEvt11CodeField] = useSessionStorage(storagePrefix + 'evt11CodeField', 'EventCode');
  const [evt11CodeValue, setEvt11CodeValue] = useSessionStorage(storagePrefix + 'evt11CodeValue', '11');
  const [evt11ProcessNameField, setEvt11ProcessNameField] = useSessionStorage(storagePrefix + 'evt11ProcessNameField', 'Image');
  const [evt11ProcessPidField, setEvt11ProcessPidField] = useSessionStorage(storagePrefix + 'evt11ProcessPidField', 'ProcessId');
  const [evt11ExtraField, setEvt11ExtraField] = useSessionStorage(storagePrefix + 'evt11ExtraField', 'TargetFilename');

  // Event 22 Config (DNS)
  const [evt22CodeField, setEvt22CodeField] = useSessionStorage(storagePrefix + 'evt22CodeField', 'EventCode');
  const [evt22CodeValue, setEvt22CodeValue] = useSessionStorage(storagePrefix + 'evt22CodeValue', '22');
  const [evt22ProcessNameField, setEvt22ProcessNameField] = useSessionStorage(storagePrefix + 'evt22ProcessNameField', 'Image');
  const [evt22ProcessPidField, setEvt22ProcessPidField] = useSessionStorage(storagePrefix + 'evt22ProcessPidField', 'ProcessId');
  const [evt22ExtraField, setEvt22ExtraField] = useSessionStorage(storagePrefix + 'evt22ExtraField', 'QueryName');

  // Event 13 Config (Registry)
  const [evt13CodeField, setEvt13CodeField] = useSessionStorage(storagePrefix + 'evt13CodeField', 'EventCode');
  const [evt13CodeValue, setEvt13CodeValue] = useSessionStorage(storagePrefix + 'evt13CodeValue', '13');
  const [evt13ProcessNameField, setEvt13ProcessNameField] = useSessionStorage(storagePrefix + 'evt13ProcessNameField', 'Image');
  const [evt13ProcessPidField, setEvt13ProcessPidField] = useSessionStorage(storagePrefix + 'evt13ProcessPidField', 'ProcessId');
  const [evt13ExtraField, setEvt13ExtraField] = useSessionStorage(storagePrefix + 'evt13ExtraField', 'TargetObject');

  // Event 4104 Config (PowerShell)
  const [evt4104CodeField, setEvt4104CodeField] = useSessionStorage(storagePrefix + 'evt4104CodeField', 'EventCode');
  const [evt4104CodeValue, setEvt4104CodeValue] = useSessionStorage(storagePrefix + 'evt4104CodeValue', '4104');
  const [evt4104ProcessPidField, setEvt4104ProcessPidField] = useSessionStorage(storagePrefix + 'evt4104ProcessPidField', 'ProcessId');
  const [evt4104ExtraField, setEvt4104ExtraField] = useSessionStorage(storagePrefix + 'evt4104ExtraField', 'ScriptBlockText');

  // Logon Context Config (4688 -> 4624)
  const [logonEventCodeField, setLogonEventCodeField] = useSessionStorage(storagePrefix + 'logonEventCodeField', 'EventCode');
  const [logonProcessNameField, setLogonProcessNameField] = useSessionStorage(storagePrefix + 'logonProcessNameField', 'Image');
  const [logonProcessPidField, setLogonProcessPidField] = useSessionStorage(storagePrefix + 'logonProcessPidField', 'ProcessId');
  const [logonIdField, setLogonIdField] = useSessionStorage(storagePrefix + 'logonIdField', 'TargetLogonId');
  const [logonHostField, setLogonHostField] = useSessionStorage(storagePrefix + 'logonHostField', 'Computer');
  const [logonSourceIpField, setLogonSourceIpField] = useSessionStorage(storagePrefix + 'logonSourceIpField', 'IpAddress');
  const [logonUserField, setLogonUserField] = useSessionStorage(storagePrefix + 'logonUserField', 'TargetUserName');
  const [logonTypeField, setLogonTypeField] = useSessionStorage(storagePrefix + 'logonTypeField', 'LogonType');
  
  // Logon Context State
  const [logonContext, setLogonContext] = useSessionStorage(storagePrefix + 'logonContext', null);
  const [isFetchingLogon, setIsFetchingLogon] = useState(false);

  // UI States
  const [openConfig, setOpenConfig] = useState('process');
  const [showActionModal, setShowActionModal] = useState(false);

  // Tree State
  const [nodes, setNodes] = useSessionStorage(storagePrefix + 'nodes', {});
  const [isBuilding, setIsBuilding] = useState(false);

  // Workspace Tabs State
  const [workspaces, setWorkspaces] = useSessionStorage(storagePrefix + 'workspaces', [
    { id: 'root', name: '🌳 Cây Gốc', isDownwardOnly: false }
  ]);
  const [activeWorkspaceId, setActiveWorkspaceId] = useSessionStorage(storagePrefix + 'activeWorkspaceId', 'root');
  const [isCaseSensitiveMatch, setIsCaseSensitiveMatch] = useSessionStorage(storagePrefix + 'isCaseSensitiveMatch', false);
  const [workspaceData, setWorkspaceData] = useSessionStorage(storagePrefix + 'workspaceData', { 'root': {} });
  const workspaceInputsRef = useRef({});

  const getFormatUrl = (url) => {
    let finalUrl = (url || '').trim();
    if (!finalUrl) return '';
    if (!finalUrl.startsWith('http://') && !finalUrl.startsWith('https://')) {
      finalUrl = 'https://' + finalUrl;
    }
    try {
      const urlObj = new URL(finalUrl);
      if (!urlObj.port && urlObj.hostname !== 'localhost') {
        urlObj.port = '8089';
      }
      return urlObj.origin;
    } catch (e) {
      return finalUrl;
    }
  };

  const [availableIndices, setAvailableIndices] = useState([]);
  const [indexFields, setIndexFields] = useState([
    '_time', 'EventCode', 'Image', 'ProcessId', 'ParentImage', 'ParentProcessId',
    'CommandLine', 'TargetUserName', 'DestinationIp', 'DestinationPort', 'TargetFilename', 'QueryName',
    'TargetObject', 'ScriptBlockText',
    'TargetLogonId', 'Computer', 'IpAddress', 'LogonType'
  ]);
  const [extraField, setExtraField] = useState('');
  const [isFullScreen, setIsFullScreen] = useState(false);
  const [expandedNodeId, setExpandedNodeId] = useState(null);
  const treeContainerRef = useRef(null);
  const [connectionStatus, setConnectionStatus] = useState(null);

  useEffect(() => {
    const handleFullScreenChange = () => {
      setIsFullScreen(!!document.fullscreenElement);
    };
    document.addEventListener('fullscreenchange', handleFullScreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullScreenChange);
  }, []);

  const handleToggleFullScreen = () => {
    if (!document.fullscreenElement) {
      const elem = treeContainerRef.current;
      if (elem && elem.requestFullscreen) {
        elem.requestFullscreen().catch(err => {
          console.error("Error attempting to enable fullscreen:", err);
          setIsFullScreen(true); // Fallback to CSS fullscreen
        });
      } else {
        setIsFullScreen(true);
      }
    } else {
      if (document.exitFullscreen) {
        document.exitFullscreen();
      }
      setIsFullScreen(false);
    }
  };

  const handleFetchFields = async (pattern) => {
    if (!pattern) return;
    try {
      const authHeader = 'Basic ' + btoa(`${username}:${password}`);
      const response = await executeQuery(`/elastic_api/${pattern}/_mapping`, {
        headers: { 
          'Authorization': authHeader,
          'x-target-url': getFormatUrl(apiUrl)
        }
      });
      if (response.ok) {
        const data = await response.json();
        const fieldsSet = new Set();

        const extractFields = (obj, prefix = '') => {
          if (obj.properties) {
            Object.keys(obj.properties).forEach(key => {
              extractFields(obj.properties[key], prefix ? `${prefix}.${key}` : key);
            });
          } else if (obj.type) {
            fieldsSet.add(prefix);
          }
        };

        Object.keys(data).forEach(indexName => {
          if (data[indexName].mappings) {
            extractFields(data[indexName].mappings);
          }
        });

        const newFields = Array.from(fieldsSet).sort();
        if (newFields.length > 0) {
           setIndexFields(newFields);
        } else {
           alert(`Không tìm thấy field nào cho index pattern: ${pattern}`);
        }
      } else {
        alert('Lỗi khi lấy Fields: ' + response.statusText);
      }
    } catch (e) {
      console.error('Lỗi khi gọi API Fields: ', e);
    }
  };

  const handleConnectAndSync = async () => {
    let baseIp = apiUrl.trim();
    if (!baseIp.startsWith('http://') && !baseIp.startsWith('https://')) {
      baseIp = 'http://' + baseIp;
    }
    
    let hasCustomPort = false;
    let urlObj = null;
    try {
       urlObj = new URL(baseIp);
       if (urlObj.port) hasCustomPort = true;
    } catch(e) {}

    const portsToTry = hasCustomPort ? [urlObj.port] : ['9200', '80', '9000', '443'];
    setConnectionStatus({ type: 'loading', message: `⏳ Đang dò tìm cổng kết nối API...` });

    const authHeader = 'Basic ' + btoa(`${username}:${password}`);
    let connected = false;

    for (let port of portsToTry) {
       let testUrl = baseIp;
       if (!hasCustomPort) {
          try {
            const u = new URL(baseIp);
            if (port === '443') u.protocol = 'https:';
            else if (port === '80') u.protocol = 'http:';
            
            if (port === '80' || port === '443') u.port = '';
            else u.port = port;
            
            testUrl = u.toString().replace(/\/$/, '');
          } catch(e) {}
       } else {
          testUrl = getFormatUrl(baseIp);
       }
       
       setConnectionStatus({ type: 'loading', message: `⏳ Đang thử kết nối cổng ${port || (testUrl.startsWith('https') ? '443' : '80')}...` });

       try {
         const response = await executeQuery(`/elastic_api/_cat/indices?format=json&h=index`, {
           headers: { 
             'Authorization': authHeader,
             'x-target-url': testUrl
           }
         });
         
         if (response.ok) {
            setApiUrl(testUrl);
            const data = await response.json();
            const indices = data.map(d => d.index).filter(i => !i.startsWith('.'));
            setAvailableIndices(indices);
            await handleFetchFields(indexPattern);
            
            setConnectionStatus({ type: 'success', message: `✅ Kết nối thành công tại cổng ${port || (testUrl.startsWith('https') ? '443' : '80')}! Đã tải Index và Fields.` });
            setTimeout(() => setConnectionStatus(null), 5000);
            connected = true;
            break;
         } else if (response.status === 401 || response.status === 403) {
            setConnectionStatus({ type: 'error', message: `❌ Tìm thấy máy chủ tại cổng ${port || (testUrl.startsWith('https') ? '443' : '80')} nhưng sai Username/Password!` });
            connected = true;
            break;
         } else if (response.status !== 502) {
            setConnectionStatus({ type: 'error', message: `❌ Lỗi kết nối (Mã lỗi ${response.status}): ` + response.statusText });
            connected = true;
            break;
         }
       } catch (e) {
         // Fall through to next port if fetch fails entirely
       }
    }

    if (!connected) {
       setConnectionStatus({ type: 'error', message: `❌ Đã quét các cổng thông dụng (9200, 80, 9000, 443) nhưng không có phản hồi! Máy ảo chưa bật hoặc sai IP.` });
    }
  };

  // Parse result hits to update nodes
  const parseSplunkTime = (tStr) => {
    if (!tStr) return 0;
    // Format: "Sep 26, 2023 @ 15:43:49.704" or similar
    let cleanStr = tStr.replace(' @ ', ' ');
    const t = new Date(cleanStr).getTime();
    if (!isNaN(t)) return t;
    
    // Fallback manual parse for Safari/Firefox
    // Expected: "Sep 26, 2023 15:43:49.704"
    const parts = cleanStr.match(/([a-zA-Z]+)\s+(\d+),\s+(\d+)\s+(\d+):(\d+):(\d+)(?:\.(\d+))?/);
    if (parts) {
      const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
      const month = months[parts[1].substring(0, 3)] || 0;
      const day = parseInt(parts[2], 10);
      const year = parseInt(parts[3], 10);
      const h = parseInt(parts[4], 10);
      const m = parseInt(parts[5], 10);
      const s = parseInt(parts[6], 10);
      const ms = parts[7] ? parseInt(parts[7].padEnd(3, '0').substring(0, 3), 10) : 0;
      return new Date(year, month, day, h, m, s, ms).getTime();
    }
    return 0;
  };



  const processHits = (hits) => {
    let currentNodes = { ...nodes };
    const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
    
    const sortedHits = [...hits].sort((a, b) => {
      const timeA = parseSplunkTime(getNested(a._source, '_time') || getNested(a._source, '@timestamp'));
      const timeB = parseSplunkTime(getNested(b._source, '_time') || getNested(b._source, '@timestamp'));
      return timeA - timeB;
    });

    sortedHits.forEach(hit => {
      const source = hit._source;
      const evtCode = getNested(source, eventCodeField)?.toString();
      if (evtCode === '1') {
        const pName = getNested(source, processNameField) || 'Unknown';
        const pPid = getNested(source, processPidField) || 'Unknown';
        const parentName = getNested(source, parentNameField) || 'Unknown';
        const parentPid = getNested(source, parentPidField) || 'Unknown';
        const time = getNested(source, '@timestamp') || '';
        
        let extraVals = [];
        if (extraField) {
          const fields = extraField.split(',').map(f => f.trim()).filter(f => f);
          fields.forEach(f => {
            const rawExtra = getNested(source, f);
            if (rawExtra) {
              const strVal = typeof rawExtra === 'object' ? JSON.stringify(rawExtra) : rawExtra.toString();
              extraVals.push(`${f}: ${strVal}`);
            }
          });
        }
        const extraStr = extraVals.join(' | ');

        const pGuid = getNested(source, processGuidField);
        const parentGuid = getNested(source, parentGuidField);

        const processId = pGuid ? pGuid : `${pName}_${pPid}`;
        const parentId = parentGuid ? parentGuid : `${parentName}_${parentPid}`;

        if (!currentNodes[processId]) {
          currentNodes[processId] = { id: processId, name: pName, pid: pPid, time: time, parents: [], children: [], extra: extraStr, fileEvents: [], regEvents: [], dnsEvents: [], networkEvents: [], isRealTime: true };
        } else {
          if (time && !currentNodes[processId].time) {
            currentNodes[processId].time = time;
            currentNodes[processId].isRealTime = true;
          }
          if (extraStr) currentNodes[processId].extra = extraStr;
          
          if (currentNodes[processId].name === "-" || currentNodes[processId].name === "Unknown") {
            currentNodes[processId].name = pName;
            currentNodes[processId].pid = pPid;
          }
        }
        
        if (!currentNodes[parentId]) {
          currentNodes[parentId] = { id: parentId, name: parentName, pid: parentPid, time: time, parents: [], children: [], extra: '', fileEvents: [], regEvents: [], dnsEvents: [], networkEvents: [], isRealTime: false };
        } else {
          if ((currentNodes[parentId].name === "-" || currentNodes[parentId].name === "Unknown") && parentName !== "-" && parentName !== "Unknown") {
            currentNodes[parentId].name = parentName;
            currentNodes[parentId].pid = parentPid;
          }
        }
        
        if (!currentNodes[parentId].children.includes(processId)) {
          currentNodes[parentId].children.push(processId);
        }
        if (!currentNodes[processId].parents.includes(parentId)) {
          currentNodes[processId].parents.push(parentId);
        }
      }
    });
    setNodes(currentNodes);
  };

  const handleBuild = async () => {
    setIsBuilding(true);
    let queryStr = '';

    const nodeVals = Object.values(nodes);
    if (nodeVals.length === 0) {
      if (!searchProcessName && !searchProcessPid) {
        alert("Vui lòng nhập Process Name hoặc PID để bắt đầu!");
        setIsBuilding(false);
        return;
      }
      let conditions = [`${eventCodeField}="1"`];
      if (searchProcessName) conditions.push(`${processNameField}="${escapeSplunk(searchProcessName)}"`);
      if (searchProcessPid) conditions.push(`${processPidField}="${searchProcessPid}"`);
      queryStr = conditions.join(" ");
    } else {
      // Bulk Expand Logic
      const roots = nodeVals.filter(n => n.parents.length === 0);
      const leaves = nodeVals.filter(n => n.parents.length > 0 && n.children.length === 0);

      // Helper to generate exclusion string for a parent node
      const getExclusionStr = (node) => {
        if (!node.children || node.children.length === 0) return "";
        const childrenByName = {};
        node.children.forEach(childId => {
          const childNode = nodeVals.find(n => n.id === childId);
          if (childNode) {
            childrenByName[childNode.name] = (childrenByName[childNode.name] || 0) + 1;
          }
        });
        
        const spamNames = Object.keys(childrenByName).filter(name => childrenByName[name] >= 10);
        if (spamNames.length > 0) {
          const excludeList = spamNames.map(name => `${processNameField}="${escapeSplunk(name)}"`).join(" OR ");
          return ` AND NOT (${excludeList})`;
        }
        return "";
      };

      const activeWorkspace = workspaces.find(w => w.id === activeWorkspaceId);
      const isDownwardOnly = activeWorkspace ? activeWorkspace.isDownwardOnly : false;

      const rootQueries = roots.map(root => {
        const excludeChildren = getExclusionStr(root);
        const isNameMissing = root.name === "-" || root.name === "Unknown";
        const selfNameCond = isNameMissing ? "" : `${processNameField}="${escapeSplunk(root.name)}" AND `;
        const parentNameCond = isNameMissing ? "" : `${parentNameField}="${escapeSplunk(root.name)}" AND `;

        if (isDownwardOnly) {
           return `(${parentNameCond}${parentPidField}="${root.pid}"${excludeChildren})`;
        } else {
           return `((${selfNameCond}${processPidField}="${root.pid}") OR (${parentNameCond}${parentPidField}="${root.pid}"${excludeChildren}))`;
        }
      });
      
      const leafQueries = leaves.map(leaf => {
        const excludeChildren = getExclusionStr(leaf);
        const isNameMissing = leaf.name === "-" || leaf.name === "Unknown";
        const parentNameCond = isNameMissing ? "" : `${parentNameField}="${escapeSplunk(leaf.name)}" AND `;
        return `(${parentNameCond}${parentPidField}="${leaf.pid}"${excludeChildren})`;
      });

      let queries = [];
      if (rootQueries.length > 0) {
        queries.push(`(${rootQueries.join(" OR ")})`);
      }
      if (leafQueries.length > 0) {
        queries.push(`(${leafQueries.join(" OR ")})`);
      }
      
      if (queries.length === 0) {
        setIsBuilding(false);
        return;
      }
      queryStr = `(${eventCodeField}="1") (${queries.join(" OR ")})`;
    }

    try {
      const authHeader = 'Basic ' + btoa(`${username}:${password}`);
      const response = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': authHeader,
          'x-target-url': getFormatUrl(apiUrl)
        },
        body: `search index="${indexPattern}" ${queryStr} | sort 0 _time | table _time, ${parentNameField}, ${parentPidField}, ${processNameField}, ${processPidField}, ${parentGuidField}, ${processGuidField}${extraField ? ", " + extraField : ""}`
      });

      if (!response.ok) {
        throw new Error(`API Error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      if (Array.isArray(data)) {
        processHits(data);
        setWorkspaces(prev => prev.map(w => {
           if (w.id === activeWorkspaceId && (w.name === '🌳 Cây Mới' || w.name === '🌳 Cây Gốc')) {
               return { ...w, name: `🌳 ${searchProcessName || searchProcessPid}` };
           }
           return w;
        }));
      } else if (data.hits && data.hits.hits && data.hits.hits.length > 0) {
        processHits(data.hits.hits);
        setWorkspaces(prev => prev.map(w => {
           if (w.id === activeWorkspaceId && (w.name === '🌳 Cây Mới' || w.name === '🌳 Cây Gốc')) {
               return { ...w, name: `🌳 ${searchProcessName || searchProcessPid}` };
           }
           return w;
        }));
      } else {
        alert("Không tìm thấy kết quả nào cho Process này!");
      }
    } catch (error) {
      alert("Lỗi khi gọi API: " + error.message + "\nNếu bị lỗi Failed to fetch, có thể do cấu hình CORS trên Elastic.");
    } finally {
      setIsBuilding(false);
    }
  };


  const handleNewTab = () => {
    const newId = 'ws_' + Date.now();
    setWorkspaceData(prev => ({
      ...prev,
      [activeWorkspaceId]: nodes,
      [newId]: {}
    }));
    setWorkspaces(prev => [...prev, { id: newId, name: `🌳 Cây Mới`, isDownwardOnly: false }]);
    // Save current inputs before creating new tab
    workspaceInputsRef.current[activeWorkspaceId] = { name: searchProcessName, pid: searchProcessPid };
    workspaceInputsRef.current[newId] = { name: '', pid: '' };
    
    setActiveWorkspaceId(newId);
    setNodes({});
    setSearchProcessName('');
    setSearchProcessPid('');
  };

  const handleDeleteBranch = (nodeId) => {
    let currentNodes = { ...nodes };
    const nodeVals = Object.values(currentNodes);
    if (nodeVals.length === 0) return;
    
    // Find absolute root
    const roots = nodeVals.filter(n => n.parents.length === 0);
    const topRoot = roots.length > 0 ? roots[0].id : null;
    
    if (nodeId === topRoot) {
      alert("Không thể xoá Node gốc trên cùng! Vui lòng dùng nút Xoá toàn bộ cây.");
      return;
    }
    
    const nodeToDelete = currentNodes[nodeId];
    if (!nodeToDelete) return;

    nodeToDelete.parents.forEach(pId => {
      if (currentNodes[pId]) {
        currentNodes[pId].children = currentNodes[pId].children.filter(id => id !== nodeId);
      }
    });

    const getDescendants = (nId) => {
      let desc = [];
      const node = currentNodes[nId];
      if (node && node.children) {
        node.children.forEach(childId => {
          desc.push(childId);
          desc = desc.concat(getDescendants(childId));
        });
      }
      return desc;
    };

    const descendants = getDescendants(nodeId);
    delete currentNodes[nodeId];
    descendants.forEach(dId => delete currentNodes[dId]);

    setNodes(currentNodes);
  };

  const handleCopyChildQuery = (node) => {
    const query = `${parentNameField}="${escapeSplunk(node.name)}" AND ${parentPidField}="${node.pid}"`;
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(query).then(() => {
        alert(`Đã copy query tìm Process Con vào Clipboard:\n${query}`);
      }).catch(() => {
        prompt("Hãy copy query bên dưới:", query);
      });
    } else {
      prompt("Hãy copy query bên dưới:", query);
    }
  };

  const handleFetchNetwork = async (node) => {
    try {
      const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
      const authHeader = 'Basic ' + btoa(`${username}:${password}`);

      let excludeList = [];
      let hasMore = true;
      const allEventsMap = {};
      
      const fetchWithExclude = async (excludes) => {
        let baseStr = `(${evt3CodeField}="${evt3CodeValue}") (${evt3ProcessNameField}="${escapeSplunk(node.name)}") (${evt3ProcessPidField}="${node.pid}")`;
        if (excludes.length > 0) {
          baseStr += ` AND (${excludes.join(" ")})`;
        }
        const response = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': authHeader,
            'x-target-url': apiUrl
          },
          body: `search index="${indexPattern}" ${baseStr} | stats count min(_time) as firstTime max(_time) as lastTime by ${evt3ProcessNameField}, ${evt3ProcessPidField}, ${evt3ExtraField}`
        });
        if (!response.ok) throw new Error(`API Error: ${response.status}`);
        return await response.json();
      };

      while (hasMore) {
        const data = await fetchWithExclude(excludeList);
        hasMore = false;
        
        if (data.hits && data.hits.hits) {
          const hits = data.hits.hits;
          let currentSpamExcludes = [];

          hits.forEach(hit => {
            const source = hit._source;
            let extraVals = [];
            let rawFields = {};
            if (evt3ExtraField) {
              const fields = evt3ExtraField.split(',').map(f => f.trim()).filter(f => f);
              fields.forEach(f => {
                const rawExtra = getNested(source, f);
                if (rawExtra) {
                  rawFields[f] = typeof rawExtra === 'object' ? JSON.stringify(rawExtra) : rawExtra.toString();
                  extraVals.push(`${f}: ${rawFields[f]}`);
                }
              });
            }
            const time = getNested(source, '@timestamp') || '';
                const extraStr = extraVals.join(' | ') || 'No Extra Data';
                const parsedCount = parseInt(getNested(source, 'count') || 1, 10);

            if (!allEventsMap[extraStr]) {
              allEventsMap[extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: parsedCount };
            } else {
              allEventsMap[extraStr].count += parsedCount;
              allEventsMap[extraStr].lastTime = time;
            }
          });

          // If we hit the limit, there might be spam blocking other events
          if (hits.length === 200) {
            const spamGroups = Object.values(allEventsMap).filter(g => g.count >= 50);
            spamGroups.forEach(g => {
              const conditions = Object.entries(g.rawFields).map(([k, v]) => `${k}: "${v}"`);
              if (conditions.length > 0) {
                const excludeStr = `NOT (${conditions.join(" ")})`;
                if (!excludeList.includes(excludeStr)) {
                  excludeList.push(excludeStr);
                  currentSpamExcludes.push(excludeStr);
                }
              }
            });

            if (currentSpamExcludes.length > 0) {
              hasMore = true; // Trigger re-query automatically
            }
          }
        }
      }

      if (Object.keys(allEventsMap).length > 0) {
        const currentNodes = { ...nodes };
        currentNodes[node.id] = { ...currentNodes[node.id] };
        
        const existingEventsMap = {};
        if (currentNodes[node.id].networkEvents) {
          currentNodes[node.id].networkEvents.forEach(e => { existingEventsMap[e.extraStr] = e; });
        }
        
        Object.values(allEventsMap).forEach(e => {
          if (existingEventsMap[e.extraStr]) {
            existingEventsMap[e.extraStr].count += e.count;
            existingEventsMap[e.extraStr].lastTime = e.lastTime;
          } else {
            existingEventsMap[e.extraStr] = e;
          }
        });

        currentNodes[node.id].networkEvents = Object.values(existingEventsMap);
        setNodes(currentNodes);
      } else {
        alert("Không tìm thấy sự kiện Network (Event 3) nào cho tiến trình này.");
      }
    } catch (error) {
      alert("Lỗi khi kéo Network: " + error.message);
    }
  };

  const handleFetchFile = async (node) => {
    try {
      const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
      const authHeader = 'Basic ' + btoa(`${username}:${password}`);

      let excludeList = [];
      let hasMore = true;
      const allEventsMap = {};
      
      const fetchWithExclude = async (excludes) => {
        let baseStr = `(${evt11CodeField}="${evt11CodeValue}") (${evt11ProcessNameField}="${escapeSplunk(node.name)}") (${evt11ProcessPidField}="${node.pid}")`;
        if (excludes.length > 0) {
          baseStr += ` AND (${excludes.join(" ")})`;
        }
        const response = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': authHeader,
            'x-target-url': apiUrl
          },
          body: `search index="${indexPattern}" ${baseStr} | stats count min(_time) as firstTime max(_time) as lastTime by ${evt11ProcessNameField}, ${evt11ProcessPidField}, ${evt11ExtraField}`
        });
        if (!response.ok) throw new Error(`API Error: ${response.status}`);
        return await response.json();
      };

      while (hasMore) {
        const data = await fetchWithExclude(excludeList);
        hasMore = false;
        
        if (data.hits && data.hits.hits) {
          const hits = data.hits.hits;
          let currentSpamExcludes = [];

          hits.forEach(hit => {
            const source = hit._source;
            let extraVals = [];
            let rawFields = {};
            if (evt11ExtraField) {
              const fields = evt11ExtraField.split(',').map(f => f.trim()).filter(f => f);
              fields.forEach(f => {
                const rawExtra = getNested(source, f);
                if (rawExtra) {
                  rawFields[f] = typeof rawExtra === 'object' ? JSON.stringify(rawExtra) : rawExtra.toString();
                  extraVals.push(`${f}: ${rawFields[f]}`);
                }
              });
            }
            const time = getNested(source, '@timestamp') || '';
                const extraStr = extraVals.join(' | ') || 'No Extra Data';
                const parsedCount = parseInt(getNested(source, 'count') || 1, 10);

            if (!allEventsMap[extraStr]) {
              allEventsMap[extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: parsedCount };
            } else {
              allEventsMap[extraStr].count += parsedCount;
              allEventsMap[extraStr].lastTime = time;
            }
          });

          if (hits.length === 200) {
            const spamGroups = Object.values(allEventsMap).filter(g => g.count >= 50);
            spamGroups.forEach(g => {
              const conditions = Object.entries(g.rawFields).map(([k, v]) => `${k}: "${v}"`);
              if (conditions.length > 0) {
                const excludeStr = `NOT (${conditions.join(" ")})`;
                if (!excludeList.includes(excludeStr)) {
                  excludeList.push(excludeStr);
                  currentSpamExcludes.push(excludeStr);
                }
              }
            });

            if (currentSpamExcludes.length > 0) {
              hasMore = true;
            }
          }
        }
      }

      if (Object.keys(allEventsMap).length > 0) {
        const currentNodes = { ...nodes };
        currentNodes[node.id] = { ...currentNodes[node.id] };
        
        const existingEventsMap = {};
        if (currentNodes[node.id].fileEvents) {
          currentNodes[node.id].fileEvents.forEach(e => { existingEventsMap[e.extraStr] = e; });
        }
        
        Object.values(allEventsMap).forEach(e => {
          if (existingEventsMap[e.extraStr]) {
            existingEventsMap[e.extraStr].count += e.count;
            existingEventsMap[e.extraStr].lastTime = e.lastTime;
          } else {
            existingEventsMap[e.extraStr] = e;
          }
        });

        currentNodes[node.id].fileEvents = Object.values(existingEventsMap);
        setNodes(currentNodes);
      } else {
        alert("Không tìm thấy sự kiện File (Event 11) nào cho tiến trình này.");
      }
    } catch (error) {
      alert("Lỗi khi kéo File: " + error.message);
    }
  };

  const handleFetchDns = async (node) => {
    try {
      const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
      const authHeader = 'Basic ' + btoa(`${username}:${password}`);

      let excludeList = [];
      let hasMore = true;
      const allEventsMap = {};
      
      const fetchWithExclude = async (excludes) => {
        let baseStr = `(${evt22CodeField}="${evt22CodeValue}") (${evt22ProcessNameField}="${escapeSplunk(node.name)}") (${evt22ProcessPidField}="${node.pid}")`;
        if (excludes.length > 0) {
          baseStr += ` AND (${excludes.join(" ")})`;
        }
        const response = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': authHeader,
            'x-target-url': getFormatUrl(apiUrl)
          },
          body: `search index="${indexPattern}" ${baseStr} | stats count min(_time) as firstTime max(_time) as lastTime by ${evt22ProcessNameField}, ${evt22ProcessPidField}, ${evt22ExtraField}`
        });
        if (!response.ok) throw new Error(`API Error: ${response.status}`);
        return await response.json();
      };

      while (hasMore) {
        const data = await fetchWithExclude(excludeList);
        hasMore = false;
        
        if (data.hits && data.hits.hits) {
          const hits = data.hits.hits;
          let currentSpamExcludes = [];

          hits.forEach(hit => {
            const source = hit._source;
            let extraVals = [];
            let rawFields = {};
            if (evt22ExtraField) {
              const fields = evt22ExtraField.split(',').map(f => f.trim()).filter(f => f);
              fields.forEach(f => {
                const rawExtra = getNested(source, f);
                if (rawExtra) {
                  rawFields[f] = typeof rawExtra === 'object' ? JSON.stringify(rawExtra) : rawExtra.toString();
                  extraVals.push(`${f}: ${rawFields[f]}`);
                }
              });
            }
            const time = getNested(source, '@timestamp') || '';
                const extraStr = extraVals.join(' | ') || 'No Extra Data';
                const parsedCount = parseInt(getNested(source, 'count') || 1, 10);

            if (!allEventsMap[extraStr]) {
              allEventsMap[extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: parsedCount };
            } else {
              allEventsMap[extraStr].count += parsedCount;
              allEventsMap[extraStr].lastTime = time;
            }
          });

          if (hits.length === 200) {
            const spamGroups = Object.values(allEventsMap).filter(g => g.count >= 50);
            spamGroups.forEach(g => {
              const conditions = Object.entries(g.rawFields).map(([k, v]) => `${k}: "${v}"`);
              if (conditions.length > 0) {
                const excludeStr = `NOT (${conditions.join(" ")})`;
                if (!excludeList.includes(excludeStr)) {
                  excludeList.push(excludeStr);
                  currentSpamExcludes.push(excludeStr);
                }
              }
            });

            if (currentSpamExcludes.length > 0) {
              hasMore = true;
            }
          }
        }
      }

      if (Object.keys(allEventsMap).length > 0) {
        const currentNodes = { ...nodes };
        currentNodes[node.id] = { ...currentNodes[node.id] };
        
        const existingEventsMap = {};
        if (currentNodes[node.id].dnsEvents) {
          currentNodes[node.id].dnsEvents.forEach(e => { existingEventsMap[e.extraStr] = e; });
        }
        
        Object.values(allEventsMap).forEach(e => {
          if (existingEventsMap[e.extraStr]) {
            existingEventsMap[e.extraStr].count += e.count;
            existingEventsMap[e.extraStr].lastTime = e.lastTime;
          } else {
            existingEventsMap[e.extraStr] = e;
          }
        });

        currentNodes[node.id].dnsEvents = Object.values(existingEventsMap);
        setNodes(currentNodes);
      } else {
        alert("Không tìm thấy sự kiện DNS (Event 22) nào cho tiến trình này.");
      }
    } catch (error) {
      alert("Lỗi khi kéo DNS: " + error.message);
    }
  };

  const handleFetchRegistry = async (node) => {
    try {
      const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
      const authHeader = 'Basic ' + btoa(`${username}:${password}`);

      let excludeList = [];
      let hasMore = true;
      const allEventsMap = {};
      
      const fetchWithExclude = async (excludes) => {
        let baseStr = `(${evt13CodeField}="${evt13CodeValue}") (${evt13ProcessNameField}="${escapeSplunk(node.name)}") (${evt13ProcessPidField}="${node.pid}")`;
        if (excludes.length > 0) {
          baseStr += ` AND (${excludes.join(" ")})`;
        }
        const response = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': authHeader,
            'x-target-url': getFormatUrl(apiUrl)
          },
          body: `search index="${indexPattern}" ${baseStr} | stats count min(_time) as firstTime max(_time) as lastTime by ${evt13ProcessNameField}, ${evt13ProcessPidField}, ${evt13ExtraField}`
        });
        if (!response.ok) throw new Error(`API Error: ${response.status}`);
        return await response.json();
      };

      while (hasMore) {
        const data = await fetchWithExclude(excludeList);
        hasMore = false;
        
        if (data.hits && data.hits.hits) {
          const hits = data.hits.hits;
          let currentSpamExcludes = [];

          hits.forEach(hit => {
            const source = hit._source;
            let extraVals = [];
            let rawFields = {};
            if (evt13ExtraField) {
              const fields = evt13ExtraField.split(',').map(f => f.trim()).filter(f => f);
              fields.forEach(f => {
                const rawExtra = getNested(source, f);
                if (rawExtra) {
                  rawFields[f] = typeof rawExtra === 'object' ? JSON.stringify(rawExtra) : rawExtra.toString();
                  extraVals.push(`${f}: ${rawFields[f]}`);
                }
              });
            }
            const time = getNested(source, '@timestamp') || '';
                const extraStr = extraVals.join(' | ') || 'No Extra Data';
                const parsedCount = parseInt(getNested(source, 'count') || 1, 10);

            if (!allEventsMap[extraStr]) {
              allEventsMap[extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: parsedCount };
            } else {
              allEventsMap[extraStr].count += parsedCount;
              allEventsMap[extraStr].lastTime = time;
            }
          });

          if (hits.length === 200) {
            const spamGroups = Object.values(allEventsMap).filter(g => g.count >= 50);
            spamGroups.forEach(g => {
              const conditions = Object.entries(g.rawFields).map(([k, v]) => `${k}: "${v}"`);
              if (conditions.length > 0) {
                const excludeStr = `NOT (${conditions.join(" ")})`;
                if (!excludeList.includes(excludeStr)) {
                  excludeList.push(excludeStr);
                  currentSpamExcludes.push(excludeStr);
                }
              }
            });

            if (currentSpamExcludes.length > 0) {
              hasMore = true;
            }
          }
        }
      }

      if (Object.keys(allEventsMap).length > 0) {
        const currentNodes = { ...nodes };
        currentNodes[node.id] = { ...currentNodes[node.id] };
        
        const existingEventsMap = {};
        if (currentNodes[node.id].regEvents) {
          currentNodes[node.id].regEvents.forEach(e => { existingEventsMap[e.extraStr] = e; });
        }
        
        Object.values(allEventsMap).forEach(e => {
          if (existingEventsMap[e.extraStr]) {
            existingEventsMap[e.extraStr].count += e.count;
            existingEventsMap[e.extraStr].lastTime = e.lastTime;
          } else {
            existingEventsMap[e.extraStr] = e;
          }
        });

        currentNodes[node.id].regEvents = Object.values(existingEventsMap);
        setNodes(currentNodes);
      } else {
        alert("Không tìm thấy sự kiện Registry (Event 13) nào cho tiến trình này.");
      }
    } catch (error) {
      alert("Lỗi khi kéo Registry: " + error.message);
    }
  };

  const handleBulkFetchNetwork = async () => {
    setIsBuilding(true);
    const nodeVals = Object.values(nodes);
    if (nodeVals.length === 0) {
      setIsBuilding(false);
      return;
    }

    const nodeQueries = nodeVals.map(n => `(${evt3ProcessNameField}="${escapeSplunk(n.name)}" AND ${evt3ProcessPidField}="${n.pid}")`);
    const chunkSize = 100;
    let currentNodes = { ...nodes };
    const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
    let foundAny = false;

    try {
      for (let i = 0; i < nodeQueries.length; i += chunkSize) {
        const chunk = nodeQueries.slice(i, i + chunkSize);
        let excludeList = [];
        let hasMore = true;
        const bulkEventsMap = {}; // { processId: { extraStr: { ... } } }
        
        while (hasMore) {
          hasMore = false;
          let queryStr = `(${evt3CodeField}="${evt3CodeValue}") (${chunk.join(" OR ")})`;
          if (excludeList.length > 0) {
            queryStr += ` AND (${excludeList.join(" ")})`;
          }

          const authHeader = 'Basic ' + btoa(`${username}:${password}`);
          const response = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': authHeader, 'x-target-url': getFormatUrl(apiUrl) },
            body: `search index="${indexPattern}" ${queryStr} | stats count min(_time) as firstTime max(_time) as lastTime by ${evt3ProcessNameField}, ${evt3ProcessPidField}, ${evt3ExtraField}`
          });

          if (!response.ok) throw new Error(`API Error: ${response.status}`);
          const data = await response.json();
          
          if (data.hits && data.hits.hits) {
            const hits = data.hits.hits;
            let currentSpamExcludes = [];

            hits.forEach(hit => {
              const source = hit._source;
              const pName = getNested(source, evt3ProcessNameField) || 'Unknown';
              const pPid = getNested(source, evt3ProcessPidField) || 'Unknown';
              const pGuid = getNested(source, processGuidField);
              let processId = null;
              if (pGuid && currentNodes[pGuid]) processId = pGuid;
              else { const n = Object.values(currentNodes).find(n => (isCaseSensitiveMatch ? n.name === pName : (n.name || '').toLowerCase() === (pName || '').toLowerCase()) && String(n.pid) === String(pPid)); if (n) processId = n.id; }
              if (processId && currentNodes[processId]) {
                let extraVals = [];
                let rawFields = {};
                if (evt3ExtraField) {
                  const fields = evt3ExtraField.split(',').map(f => f.trim()).filter(f => f);
                  fields.forEach(f => {
                    const rawExtra = getNested(source, f);
                    if (rawExtra) {
                      rawFields[f] = typeof rawExtra === 'object' ? JSON.stringify(rawExtra) : rawExtra.toString();
                      extraVals.push(`${f}: ${rawFields[f]}`);
                    }
                  });
                }
                const time = getNested(source, '@timestamp') || '';
                const extraStr = extraVals.join(' | ') || 'No Extra Data';
                const parsedCount = parseInt(getNested(source, 'count') || 1, 10);

                if (!bulkEventsMap[processId]) bulkEventsMap[processId] = {};
                if (!bulkEventsMap[processId][extraStr]) {
                  bulkEventsMap[processId][extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: parsedCount };
                } else {
                  bulkEventsMap[processId][extraStr].count += parsedCount;
                  bulkEventsMap[processId][extraStr].lastTime = time;
                }
              }
            });

            if (hits.length === 5000) {
              Object.values(bulkEventsMap).forEach(procMap => {
                const spamGroups = Object.values(procMap).filter(g => g.count >= 200);
                spamGroups.forEach(g => {
                  const conditions = Object.entries(g.rawFields).map(([k, v]) => `${k}: "${v}"`);
                  if (conditions.length > 0) {
                    const excludeStr = `NOT (${conditions.join(" ")})`;
                    if (!excludeList.includes(excludeStr)) {
                      excludeList.push(excludeStr);
                      currentSpamExcludes.push(excludeStr);
                    }
                  }
                });
              });

              if (currentSpamExcludes.length > 0) {
                hasMore = true; // Auto re-query to bypass spam limit
              }
            }
          }
        } // End while hasMore
        
        // Merge bulkEventsMap into currentNodes
        Object.keys(bulkEventsMap).forEach(pId => {
          if (currentNodes[pId]) {
            currentNodes[pId] = { ...currentNodes[pId] }; // Clone to mutate
            const existingMap = {};
            if (currentNodes[pId].networkEvents) {
              currentNodes[pId].networkEvents.forEach(e => { existingMap[e.extraStr] = e; });
            }
            
            Object.values(bulkEventsMap[pId]).forEach(e => {
              if (existingMap[e.extraStr]) {
                existingMap[e.extraStr].count += e.count;
                existingMap[e.extraStr].lastTime = e.lastTime;
              } else {
                existingMap[e.extraStr] = e;
              }
            });
            
            const newEvents = Object.values(existingMap);
            if (newEvents.length > 0) {
              currentNodes[pId].networkEvents = newEvents;
              foundAny = true;
            }
          }
        });
      }

      if (foundAny) {
        setNodes(currentNodes);
        alert("✅ Đã hoàn tất kéo sự kiện Network (Event 3) cho toàn bộ Cây!");
      } else {
        alert("Không tìm thấy sự kiện Network nào mới cho các tiến trình hiện tại.");
      }
    } catch (error) {
      alert("Lỗi khi kéo Network tổng: " + error.message);
    } finally {
      setIsBuilding(false);
    }
  };

  const handleBulkFetchFile = async () => {
    setIsBuilding(true);
    const nodeVals = Object.values(nodes);
    if (nodeVals.length === 0) {
      setIsBuilding(false);
      return;
    }

    const nodeQueries = nodeVals.map(n => `(${evt11ProcessNameField}="${escapeSplunk(n.name)}" AND ${evt11ProcessPidField}="${n.pid}")`);
    const chunkSize = 100;
    let currentNodes = { ...nodes };
    const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
    let foundAny = false;

    try {
      for (let i = 0; i < nodeQueries.length; i += chunkSize) {
        const chunk = nodeQueries.slice(i, i + chunkSize);
        let excludeList = [];
        let hasMore = true;
        const bulkEventsMap = {};
        
        while (hasMore) {
          hasMore = false;
          let queryStr = `(${evt11CodeField}="${evt11CodeValue}") (${chunk.join(" OR ")})`;
          if (excludeList.length > 0) {
            queryStr += ` AND (${excludeList.join(" ")})`;
          }

          const authHeader = 'Basic ' + btoa(`${username}:${password}`);
          const response = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': authHeader, 'x-target-url': getFormatUrl(apiUrl) },
            body: `search index="${indexPattern}" ${queryStr} | stats count min(_time) as firstTime max(_time) as lastTime by ${evt11ProcessNameField}, ${evt11ProcessPidField}, ${evt11ExtraField}`
          });

          if (!response.ok) throw new Error(`API Error: ${response.status}`);
          const data = await response.json();
          
          if (data.hits && data.hits.hits) {
            const hits = data.hits.hits;
            let currentSpamExcludes = [];

            hits.forEach(hit => {
              const source = hit._source;
              const pName = getNested(source, evt11ProcessNameField) || 'Unknown';
              const pPid = getNested(source, evt11ProcessPidField) || 'Unknown';
              const pGuid = getNested(source, processGuidField);
              let processId = null;
              if (pGuid && currentNodes[pGuid]) processId = pGuid;
              else { const n = Object.values(currentNodes).find(n => (isCaseSensitiveMatch ? n.name === pName : (n.name || '').toLowerCase() === (pName || '').toLowerCase()) && String(n.pid) === String(pPid)); if (n) processId = n.id; }
              if (processId && currentNodes[processId]) {
                let extraVals = [];
                let rawFields = {};
                if (evt11ExtraField) {
                  const fields = evt11ExtraField.split(',').map(f => f.trim()).filter(f => f);
                  fields.forEach(f => {
                    const rawExtra = getNested(source, f);
                    if (rawExtra) {
                      rawFields[f] = typeof rawExtra === 'object' ? JSON.stringify(rawExtra) : rawExtra.toString();
                      extraVals.push(`${f}: ${rawFields[f]}`);
                    }
                  });
                }
                const time = getNested(source, '@timestamp') || '';
                const extraStr = extraVals.join(' | ') || 'No Extra Data';
                const parsedCount = parseInt(getNested(source, 'count') || 1, 10);

                if (!bulkEventsMap[processId]) bulkEventsMap[processId] = {};
                if (!bulkEventsMap[processId][extraStr]) {
                  bulkEventsMap[processId][extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: parsedCount };
                } else {
                  bulkEventsMap[processId][extraStr].count += parsedCount;
                  bulkEventsMap[processId][extraStr].lastTime = time;
                }
              }
            });

            if (hits.length === 5000) {
              Object.values(bulkEventsMap).forEach(procMap => {
                const spamGroups = Object.values(procMap).filter(g => g.count >= 200);
                spamGroups.forEach(g => {
                  const conditions = Object.entries(g.rawFields).map(([k, v]) => `${k}: "${v}"`);
                  if (conditions.length > 0) {
                    const excludeStr = `NOT (${conditions.join(" ")})`;
                    if (!excludeList.includes(excludeStr)) {
                      excludeList.push(excludeStr);
                      currentSpamExcludes.push(excludeStr);
                    }
                  }
                });
              });

              if (currentSpamExcludes.length > 0) {
                hasMore = true;
              }
            }
          }
        }
        
        Object.keys(bulkEventsMap).forEach(pId => {
          if (currentNodes[pId]) {
            currentNodes[pId] = { ...currentNodes[pId] };
            const existingMap = {};
            if (currentNodes[pId].fileEvents) {
              currentNodes[pId].fileEvents.forEach(e => { existingMap[e.extraStr] = e; });
            }
            
            Object.values(bulkEventsMap[pId]).forEach(e => {
              if (existingMap[e.extraStr]) {
                existingMap[e.extraStr].count += e.count;
                existingMap[e.extraStr].lastTime = e.lastTime;
              } else {
                existingMap[e.extraStr] = e;
              }
            });
            
            const newEvents = Object.values(existingMap);
            if (newEvents.length > 0) {
              currentNodes[pId].fileEvents = newEvents;
              foundAny = true;
            }
          }
        });
      }

      if (foundAny) {
        setNodes(currentNodes);
        alert("✅ Đã hoàn tất kéo sự kiện File (Event 11) cho toàn bộ Cây!");
      } else {
        alert("Không tìm thấy sự kiện File nào mới cho các tiến trình hiện tại.");
      }
    } catch (error) {
      alert("Lỗi khi kéo File tổng: " + error.message);
    } finally {
      setIsBuilding(false);
    }
  };

  const handleBulkFetchDns = async () => {
    setIsBuilding(true);
    const nodeVals = Object.values(nodes);
    if (nodeVals.length === 0) {
      setIsBuilding(false);
      return;
    }

    const nodeQueries = nodeVals.map(n => `(${evt22ProcessNameField}="${escapeSplunk(n.name)}" AND ${evt22ProcessPidField}="${n.pid}")`);
    const chunkSize = 100;
    let currentNodes = { ...nodes };
    const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
    let foundAny = false;

    try {
      for (let i = 0; i < nodeQueries.length; i += chunkSize) {
        const chunk = nodeQueries.slice(i, i + chunkSize);
        let excludeList = [];
        let hasMore = true;
        const bulkEventsMap = {}; 
        
        while (hasMore) {
          hasMore = false;
          let queryStr = `(${evt22CodeField}="${evt22CodeValue}") (${chunk.join(" OR ")})`;
          if (excludeList.length > 0) {
            queryStr += ` AND (${excludeList.join(" ")})`;
          }

          const authHeader = 'Basic ' + btoa(`${username}:${password}`);
          const response = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': authHeader, 'x-target-url': getFormatUrl(apiUrl) },
            body: `search index="${indexPattern}" ${queryStr} | stats count min(_time) as firstTime max(_time) as lastTime by ${evt22ProcessNameField}, ${evt22ProcessPidField}, ${evt22ExtraField}`
          });

          if (!response.ok) throw new Error(`API Error: ${response.status}`);
          const data = await response.json();
          
          if (data.hits && data.hits.hits) {
            const hits = data.hits.hits;
            let currentSpamExcludes = [];

            hits.forEach(hit => {
              const source = hit._source;
              const pName = getNested(source, evt22ProcessNameField) || 'Unknown';
              const pPid = getNested(source, evt22ProcessPidField) || 'Unknown';
              const pGuid = getNested(source, processGuidField);
              let processId = null;
              if (pGuid && currentNodes[pGuid]) processId = pGuid;
              else { const n = Object.values(currentNodes).find(n => (isCaseSensitiveMatch ? n.name === pName : (n.name || '').toLowerCase() === (pName || '').toLowerCase()) && String(n.pid) === String(pPid)); if (n) processId = n.id; }
              if (processId && currentNodes[processId]) {
                let extraVals = [];
                let rawFields = {};
                if (evt22ExtraField) {
                  const fields = evt22ExtraField.split(',').map(f => f.trim()).filter(f => f);
                  fields.forEach(f => {
                    const rawExtra = getNested(source, f);
                    if (rawExtra) {
                      rawFields[f] = typeof rawExtra === 'object' ? JSON.stringify(rawExtra) : rawExtra.toString();
                      extraVals.push(`${f}: ${rawFields[f]}`);
                    }
                  });
                }
                const time = getNested(source, '@timestamp') || '';
                const extraStr = extraVals.join(' | ') || 'No Extra Data';
                const parsedCount = parseInt(getNested(source, 'count') || 1, 10);

                if (!bulkEventsMap[processId]) bulkEventsMap[processId] = {};
                if (!bulkEventsMap[processId][extraStr]) {
                  bulkEventsMap[processId][extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: parsedCount };
                } else {
                  bulkEventsMap[processId][extraStr].count += parsedCount;
                  bulkEventsMap[processId][extraStr].lastTime = time;
                }
              }
            });

            if (hits.length === 5000) {
              Object.values(bulkEventsMap).forEach(procMap => {
                const spamGroups = Object.values(procMap).filter(g => g.count >= 200);
                spamGroups.forEach(g => {
                  const conditions = Object.entries(g.rawFields).map(([k, v]) => `${k}: "${v}"`);
                  if (conditions.length > 0) {
                    const excludeStr = `NOT (${conditions.join(" ")})`;
                    if (!excludeList.includes(excludeStr)) {
                      excludeList.push(excludeStr);
                      currentSpamExcludes.push(excludeStr);
                    }
                  }
                });
              });

              if (currentSpamExcludes.length > 0) {
                hasMore = true;
              }
            }
          }
        }

        Object.keys(bulkEventsMap).forEach(pId => {
          if (Object.keys(bulkEventsMap[pId]).length > 0) {
            const existingMap = {};
            if (currentNodes[pId].dnsEvents) {
              currentNodes[pId].dnsEvents.forEach(e => { existingMap[e.extraStr] = e; });
            }
            
            Object.values(bulkEventsMap[pId]).forEach(e => {
              if (existingMap[e.extraStr]) {
                existingMap[e.extraStr].count += e.count;
                existingMap[e.extraStr].lastTime = e.lastTime;
              } else {
                existingMap[e.extraStr] = e;
              }
            });
            
            const newEvents = Object.values(existingMap);
            if (newEvents.length > 0) {
              currentNodes[pId].dnsEvents = newEvents;
              foundAny = true;
            }
          }
        });
      }

      if (foundAny) {
        setNodes(currentNodes);
        alert("✅ Đã hoàn tất kéo sự kiện DNS (Event 22) cho toàn bộ Cây!");
      } else {
        alert("Không tìm thấy sự kiện DNS nào mới cho các tiến trình hiện tại.");
      }
    } catch (error) {
      alert("Lỗi khi kéo DNS tổng: " + error.message);
    } finally {
      setIsBuilding(false);
    }
  };

  const handleBulkFetchRegistry = async () => {
    setIsBuilding(true);
    const nodeVals = Object.values(nodes);
    if (nodeVals.length === 0) {
      setIsBuilding(false);
      return;
    }

    const nodeQueries = nodeVals.map(n => `(${evt13ProcessNameField}="${escapeSplunk(n.name)}" AND ${evt13ProcessPidField}="${n.pid}")`);
    const chunkSize = 100;
    let currentNodes = { ...nodes };
    const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
    let foundAny = false;

    try {
      for (let i = 0; i < nodeQueries.length; i += chunkSize) {
        const chunk = nodeQueries.slice(i, i + chunkSize);
        let excludeList = [];
        let hasMore = true;
        const bulkEventsMap = {}; 
        
        while (hasMore) {
          hasMore = false;
          let queryStr = `(${evt13CodeField}="${evt13CodeValue}") (${chunk.join(" OR ")})`;
          if (excludeList.length > 0) {
            queryStr += ` AND (${excludeList.join(" ")})`;
          }

          const authHeader = 'Basic ' + btoa(`${username}:${password}`);
          const response = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': authHeader, 'x-target-url': getFormatUrl(apiUrl) },
            body: `search index="${indexPattern}" ${queryStr} | stats count min(_time) as firstTime max(_time) as lastTime by ${evt13ProcessNameField}, ${evt13ProcessPidField}, ${evt13ExtraField}`
          });

          if (!response.ok) throw new Error(`API Error: ${response.status}`);
          const data = await response.json();
          
          if (data.hits && data.hits.hits) {
            const hits = data.hits.hits;
            let currentSpamExcludes = [];

            hits.forEach(hit => {
              const source = hit._source;
              const pName = getNested(source, evt13ProcessNameField) || 'Unknown';
              const pPid = getNested(source, evt13ProcessPidField) || 'Unknown';
              const pGuid = getNested(source, processGuidField);
              let processId = null;
              if (pGuid && currentNodes[pGuid]) processId = pGuid;
              else { const n = Object.values(currentNodes).find(n => (isCaseSensitiveMatch ? n.name === pName : (n.name || '').toLowerCase() === (pName || '').toLowerCase()) && String(n.pid) === String(pPid)); if (n) processId = n.id; }
              if (processId && currentNodes[processId]) {
                let extraVals = [];
                let rawFields = {};
                if (evt13ExtraField) {
                  const fields = evt13ExtraField.split(',').map(f => f.trim()).filter(f => f);
                  fields.forEach(f => {
                    const rawExtra = getNested(source, f);
                    if (rawExtra) {
                      rawFields[f] = typeof rawExtra === 'object' ? JSON.stringify(rawExtra) : rawExtra.toString();
                      extraVals.push(`${f}: ${rawFields[f]}`);
                    }
                  });
                }
                const time = getNested(source, '@timestamp') || '';
                const extraStr = extraVals.join(' | ') || 'No Extra Data';
                const parsedCount = parseInt(getNested(source, 'count') || 1, 10);

                if (!bulkEventsMap[processId]) bulkEventsMap[processId] = {};
                if (!bulkEventsMap[processId][extraStr]) {
                  bulkEventsMap[processId][extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: parsedCount };
                } else {
                  bulkEventsMap[processId][extraStr].count += parsedCount;
                  bulkEventsMap[processId][extraStr].lastTime = time;
                }
              }
            });

            if (hits.length === 5000) {
              Object.values(bulkEventsMap).forEach(procMap => {
                const spamGroups = Object.values(procMap).filter(g => g.count >= 200);
                spamGroups.forEach(g => {
                  const conditions = Object.entries(g.rawFields).map(([k, v]) => `${k}: "${v}"`);
                  if (conditions.length > 0) {
                    const excludeStr = `NOT (${conditions.join(" ")})`;
                    if (!excludeList.includes(excludeStr)) {
                      excludeList.push(excludeStr);
                      currentSpamExcludes.push(excludeStr);
                    }
                  }
                });
              });

              if (currentSpamExcludes.length > 0) {
                hasMore = true;
              }
            }
          }
        }

        Object.keys(bulkEventsMap).forEach(pId => {
          if (Object.keys(bulkEventsMap[pId]).length > 0) {
            const existingMap = {};
            if (currentNodes[pId].regEvents) {
              currentNodes[pId].regEvents.forEach(e => { existingMap[e.extraStr] = e; });
            }
            
            Object.values(bulkEventsMap[pId]).forEach(e => {
              if (existingMap[e.extraStr]) {
                existingMap[e.extraStr].count += e.count;
                existingMap[e.extraStr].lastTime = e.lastTime;
              } else {
                existingMap[e.extraStr] = e;
              }
            });
            
            const newEvents = Object.values(existingMap);
            if (newEvents.length > 0) {
              currentNodes[pId].regEvents = newEvents;
              foundAny = true;
            }
          }
        });
      }

      if (foundAny) {
        setNodes(currentNodes);
        alert("✅ Đã hoàn tất kéo sự kiện Registry (Event 13) cho toàn bộ Cây!");
      } else {
        alert("Không tìm thấy sự kiện Registry nào mới cho các tiến trình hiện tại.");
      }
    } catch (error) {
      alert("Lỗi khi kéo Registry tổng: " + error.message);
    } finally {
      setIsBuilding(false);
    }
  };

  const handleFetchPowerShell = async (node) => {
    try {
      const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
      const authHeader = 'Basic ' + btoa(`${username}:${password}`);

      let excludeList = [];
      let hasMore = true;
      const allEventsMap = {};
      
      const fetchWithExclude = async (excludes) => {
        let baseStr = `(${evt4104CodeField}="${evt4104CodeValue}") (${evt4104ProcessPidField}="${node.pid}")`;
        if (excludes.length > 0) {
          baseStr += ` AND (${excludes.join(" ")})`;
        }
        const response = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': authHeader, 'x-target-url': getFormatUrl(apiUrl) },
          body: `search index="${indexPattern}" ${baseStr} | stats count min(_time) as firstTime max(_time) as lastTime by ${evt4104ProcessPidField}, ${evt4104ExtraField}`
        });
        if (!response.ok) throw new Error(`API Error: ${response.status}`);
        return await response.json();
      };

      while (hasMore) {
        const data = await fetchWithExclude(excludeList);
        hasMore = false;
        
        if (data.hits && data.hits.hits) {
          const hits = data.hits.hits;
          let currentSpamExcludes = [];

          hits.forEach(hit => {
            const source = hit._source;
            let extraVals = [];
            let rawFields = {};
            if (evt4104ExtraField) {
              const fields = evt4104ExtraField.split(',').map(f => f.trim()).filter(f => f);
              fields.forEach(f => {
                const rawExtra = getNested(source, f);
                if (rawExtra) {
                  rawFields[f] = typeof rawExtra === 'object' ? JSON.stringify(rawExtra) : rawExtra.toString();
                  extraVals.push(`${f}: ${rawFields[f]}`);
                }
              });
            }
            const time = getNested(source, '@timestamp') || '';
                const extraStr = extraVals.join(' | ') || 'No Extra Data';
                const parsedCount = parseInt(getNested(source, 'count') || 1, 10);

            if (!allEventsMap[extraStr]) {
              allEventsMap[extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: parsedCount };
            } else {
              allEventsMap[extraStr].count += parsedCount;
              allEventsMap[extraStr].lastTime = time;
            }
          });

          if (hits.length === 200) {
            const spamGroups = Object.values(allEventsMap).filter(g => g.count >= 50);
            spamGroups.forEach(g => {
              const conditions = Object.entries(g.rawFields).map(([k, v]) => {
                const safeVal = v.replace(/"/g, '\\"');
                return `${k}: "${safeVal}"`;
              });
              if (conditions.length > 0) {
                const excludeStr = `NOT (${conditions.join(" ")})`;
                if (!excludeList.includes(excludeStr)) {
                  excludeList.push(excludeStr);
                  currentSpamExcludes.push(excludeStr);
                }
              }
            });

            if (currentSpamExcludes.length > 0) {
              hasMore = true;
            }
          }
        }
      }

      if (Object.keys(allEventsMap).length > 0) {
        const currentNodes = { ...nodes };
        currentNodes[node.id] = { ...currentNodes[node.id] };
        
        const existingEventsMap = {};
        if (currentNodes[node.id].psEvents) {
          currentNodes[node.id].psEvents.forEach(e => { existingEventsMap[e.extraStr] = e; });
        }
        
        Object.values(allEventsMap).forEach(e => {
          if (existingEventsMap[e.extraStr]) {
            existingEventsMap[e.extraStr].count += e.count;
            existingEventsMap[e.extraStr].lastTime = e.lastTime;
          } else {
            existingEventsMap[e.extraStr] = e;
          }
        });

        currentNodes[node.id].psEvents = Object.values(existingEventsMap);
        setNodes(currentNodes);
      } else {
        alert("Không tìm thấy sự kiện PowerShell (Event 4104) nào cho tiến trình này.");
      }
    } catch (error) {
      alert("Lỗi khi kéo PowerShell Event 4104: " + error.message);
    }
  };

  const handleBulkFetchPowerShell = async () => {
    setIsBuilding(true);
    const nodeVals = Object.values(nodes);
    if (nodeVals.length === 0) {
      setIsBuilding(false);
      return;
    }

    const nodeQueries = nodeVals.map(n => `(${evt4104ProcessPidField}="${n.pid}")`);
    const chunkSize = 100;
    let currentNodes = { ...nodes };
    const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
    let foundAny = false;

    try {
      for (let i = 0; i < nodeQueries.length; i += chunkSize) {
        const chunk = nodeQueries.slice(i, i + chunkSize);
        let excludeList = [];
        let hasMore = true;
        const bulkEventsMap = {}; 
        
        while (hasMore) {
          hasMore = false;
          let queryStr = `(${evt4104CodeField}="${evt4104CodeValue}") (${chunk.join(" OR ")})`;
          if (excludeList.length > 0) {
            queryStr += ` AND (${excludeList.join(" ")})`;
          }

          const authHeader = 'Basic ' + btoa(`${username}:${password}`);
          const response = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': authHeader, 'x-target-url': getFormatUrl(apiUrl) },
            body: `search index="${indexPattern}" ${queryStr} | stats count min(_time) as firstTime max(_time) as lastTime by ${evt4104ProcessPidField}, ${evt4104ExtraField}`
          });

          if (!response.ok) throw new Error(`API Error: ${response.status}`);
          const data = await response.json();
          
          if (data.hits && data.hits.hits) {
            const hits = data.hits.hits;
            let currentSpamExcludes = [];

            hits.forEach(hit => {
              const source = hit._source;
              const pPid = getNested(source, evt4104ProcessPidField) || 'Unknown';
              
              const matchingNodeIds = Object.keys(currentNodes).filter(k => currentNodes[k].pid === pPid);

              matchingNodeIds.forEach(processId => {
                let extraVals = [];
                let rawFields = {};
                if (evt4104ExtraField) {
                  const fields = evt4104ExtraField.split(',').map(f => f.trim()).filter(f => f);
                  fields.forEach(f => {
                    const rawExtra = getNested(source, f);
                    if (rawExtra) {
                      rawFields[f] = typeof rawExtra === 'object' ? JSON.stringify(rawExtra) : rawExtra.toString();
                      extraVals.push(`${f}: ${rawFields[f]}`);
                    }
                  });
                }
                const time = getNested(source, '@timestamp') || '';
                const extraStr = extraVals.join(' | ') || 'No Extra Data';
                const parsedCount = parseInt(getNested(source, 'count') || 1, 10);

                if (!bulkEventsMap[processId]) bulkEventsMap[processId] = {};
                if (!bulkEventsMap[processId][extraStr]) {
                  bulkEventsMap[processId][extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: parsedCount };
                } else {
                  bulkEventsMap[processId][extraStr].count += parsedCount;
                  bulkEventsMap[processId][extraStr].lastTime = time;
                }
              });
            });

            if (hits.length === 5000) {
              Object.values(bulkEventsMap).forEach(procMap => {
                const spamGroups = Object.values(procMap).filter(g => g.count >= 200);
                spamGroups.forEach(g => {
                  const conditions = Object.entries(g.rawFields).map(([k, v]) => {
                    const safeVal = v.replace(/"/g, '\\"');
                    return `${k}: "${safeVal}"`;
                  });
                  if (conditions.length > 0) {
                    const excludeStr = `NOT (${conditions.join(" ")})`;
                    if (!excludeList.includes(excludeStr)) {
                      excludeList.push(excludeStr);
                      currentSpamExcludes.push(excludeStr);
                    }
                  }
                });
              });

              if (currentSpamExcludes.length > 0) {
                hasMore = true;
              }
            }
          }
        }

        Object.keys(bulkEventsMap).forEach(pId => {
          if (Object.keys(bulkEventsMap[pId]).length > 0) {
            const existingMap = {};
            if (currentNodes[pId].psEvents) {
              currentNodes[pId].psEvents.forEach(e => { existingMap[e.extraStr] = e; });
            }
            
            Object.values(bulkEventsMap[pId]).forEach(e => {
              if (existingMap[e.extraStr]) {
                existingMap[e.extraStr].count += e.count;
                existingMap[e.extraStr].lastTime = e.lastTime;
              } else {
                existingMap[e.extraStr] = e;
              }
            });
            
            const newEvents = Object.values(existingMap);
            if (newEvents.length > 0) {
              currentNodes[pId].psEvents = newEvents;
              foundAny = true;
            }
          }
        });
      }

      if (foundAny) {
        setNodes(currentNodes);
        alert("✅ Đã hoàn tất kéo sự kiện PowerShell (Event 4104) cho toàn bộ Cây!");
      } else {
        alert("Không tìm thấy sự kiện PowerShell nào mới cho các tiến trình hiện tại.");
      }
    } catch (error) {
      alert("Lỗi khi kéo PowerShell tổng: " + error.message);
    } finally {
      setIsBuilding(false);
    }
  };


  const handleGeneratePrompt = () => {
    const nodeVals = Object.values(nodes);
    if (nodeVals.length === 0) {
      alert("Cây hiện tại đang trống. Vui lòng build cây trước!");
      return;
    }

    let roots = nodeVals.filter(n => n.parents.length === 0);
    if (roots.length === 0) roots = [nodeVals[0]];
    
    roots.sort((a, b) => {
      const timeA = new Date(a.time || 0).getTime() || 0;
      const timeB = new Date(b.time || 0).getTime() || 0;
      return timeA - timeB;
    });

    let treeText = "";
    
    const buildTextNode = (nodeId, prefix = '', isLast = true) => {
      const node = nodes[nodeId];
      if (!node) return;

      const linePrefix = prefix + (isLast ? '└── ' : '├── ');
      treeText += `${linePrefix}[Process] ${node.name} (PID: ${node.pid}) [${node.time}] ${node.extra ? `| Extra: ${node.extra}` : ''}\n`;

      const childPrefix = prefix + (isLast ? '    ' : '│   ');

      if (node.networkEvents && node.networkEvents.length > 0) {
        node.networkEvents.forEach(evt => {
           treeText += `${childPrefix}├── [Network] ${evt.extraStr} (x${evt.count})\n`;
        });
      }
      
      if (node.fileEvents && node.fileEvents.length > 0) {
        node.fileEvents.forEach(evt => {
           treeText += `${childPrefix}├── [File] ${evt.extraStr} (x${evt.count})\n`;
        });
      }

      if (node.dnsEvents && node.dnsEvents.length > 0) {
        node.dnsEvents.forEach(evt => {
           treeText += `${childPrefix}├── [DNS] ${evt.extraStr} (x${evt.count})\n`;
        });
      }
      
      if (node.regEvents && node.regEvents.length > 0) {
        node.regEvents.forEach(evt => {
           treeText += `${childPrefix}├── [Registry] ${evt.extraStr} (x${evt.count})\n`;
        });
      }

      if (node.psEvents && node.psEvents.length > 0) {
        node.psEvents.forEach(evt => {
           treeText += `${childPrefix}├── [PowerShell Script] ${evt.extraStr} (x${evt.count})\n`;
        });
      }

      const sortedChildren = [...node.children].sort((aId, bId) => {
        const timeA = new Date(nodes[aId]?.time || 0).getTime() || 0;
        const timeB = new Date(nodes[bId]?.time || 0).getTime() || 0;
        return timeA - timeB;
      });

      sortedChildren.forEach((childId, index) => {
        buildTextNode(childId, childPrefix, index === sortedChildren.length - 1);
      });
    };

    roots.forEach((root, idx) => {
      buildTextNode(root.id, '', idx === roots.length - 1);
    });

    const promptText = `Dưới đây là một cây tiến trình (Process Tree) trích xuất từ hệ thống Windows bằng Sysmon/Elasticsearch.\nCác nhánh bao gồm sự kiện Network, File, DNS, Registry và mã nguồn PowerShell script.\n\n\`\`\`\n${treeText}\`\`\`\n\nHãy đóng vai một chuyên gia Cyber Security / Threat Hunter phân tích chuỗi sự kiện này:\n1. Bạn có thấy dấu hiệu nào nguy hiểm hoặc bất thường không? (Ví dụ: Malware, C2 Communication, Lateral Movement, Privilege Escalation, Obfuscated PowerShell...)\n2. Chỉ ra chính xác các chi tiết đáng ngờ trên cây.\n3. Đề xuất hướng tiếp cận tiếp theo để điều tra hoặc xử lý.`;

    navigator.clipboard.writeText(promptText).then(() => {
      alert("✅ Đã copy Prompt AI thành công! Bạn có thể dán vào ChatGPT/Claude để phân tích.");
    }).catch(err => {
      alert("❌ Không thể copy, vui lòng thử lại! " + err);
    });
  };

  const handleFetchLogonContext = async () => {
    const nodeVals = Object.values(nodes);
    const roots = nodeVals.filter(n => n.parents.length === 0);
    const topRoot = roots.length > 0 ? roots[0] : null;
    if (!topRoot) {
      alert("Không tìm thấy tiến trình gốc nào trong cây hiện tại.");
      return;
    }
    
    setIsFetchingLogon(true);
    setLogonContext(null);

    try {
      const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
      const authHeader = 'Basic ' + btoa(`${username}:${password}`);

      // 1. Fetch Event 4688 to get Logon ID
      let q1 = `(${logonEventCodeField}="4688") (${logonProcessNameField}="${escapeSplunk(topRoot.name)}") (${logonProcessPidField}="${topRoot.pid}")`;
      const res1 = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': authHeader, 'x-target-url': getFormatUrl(apiUrl) },
        body: `search index="${indexPattern}" ${q1} | sort 0 _time | table _time, ${logonIdField}, ${logonUserField}, ${logonHostField}, ${logonSourceIpField}, ${logonTypeField}`
      });
      if (!res1.ok) throw new Error(`API Error 4688: ${res1.status}`);
      const data1 = await res1.json();
      
      if (!data1.hits || !data1.hits.hits || data1.hits.hits.length === 0) {
        alert("Không tìm thấy Event 4688 (Process Creation) nào cho Process Name và PID này.");
        setIsFetchingLogon(false);
        return;
      }
      
      const source1 = data1.hits.hits[0]._source;
      const logonId = getNested(source1, logonIdField);
      
      if (!logonId) {
        alert(`Không tìm thấy giá trị '${logonIdField}' trong Event 4688.`);
        setIsFetchingLogon(false);
        return;
      }

      // 2. Fetch Event 4624 using Logon ID
      let q2 = `(${logonEventCodeField}="4624") (${logonIdField}="${escapeSplunk(logonId)}")`;
      const res2 = await executeQuery(`/elastic_api/${indexPattern}/_search`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': authHeader, 'x-target-url': getFormatUrl(apiUrl) },
        body: `search index="${indexPattern}" ${q2} | sort 0 _time | table _time, ${logonIdField}, ${logonUserField}, ${logonHostField}, ${logonSourceIpField}, ${logonTypeField}`
      });
      if (!res2.ok) throw new Error(`API Error 4624: ${res2.status}`);
      const data2 = await res2.json();

      if (!data2.hits || !data2.hits.hits || data2.hits.hits.length === 0) {
        alert(`Đã tìm thấy Logon ID: ${logonId} nhưng không tìm thấy Event 4624 tương ứng.`);
        setIsFetchingLogon(false);
        return;
      }

      const source2 = data2.hits.hits[0]._source;
      const host = getNested(source2, logonHostField) || 'N/A';
      const ip = getNested(source2, logonSourceIpField) || 'N/A';
      const user = getNested(source2, logonUserField) || 'N/A';
      const logonType = getNested(source2, logonTypeField) || 'N/A';

      setLogonContext({
        logonId, host, ip, user, logonType
      });

    } catch (error) {
      alert("Lỗi khi tra cứu Logon Context: " + error.message);
    } finally {
      setIsFetchingLogon(false);
    }
  };

  const handlePruneSpam = () => {
    const currentNodes = { ...nodes };
    let deletedCount = 0;

    const getDescendants = (nId) => {
      let desc = [];
      const node = currentNodes[nId];
      if (node && node.children) {
        node.children.forEach(childId => {
          desc.push(childId);
          desc = desc.concat(getDescendants(childId));
        });
      }
      return desc;
    };

    Object.values(currentNodes).forEach(node => {
      if (node && node.children && node.children.length > 10) {
        const leafChildrenByName = {};
        
        node.children.forEach(childId => {
          const childNode = currentNodes[childId];
          // Chỉ coi là spam nếu nó là nút LÁ (chưa đẻ ra thêm process con nào)
          if (childNode && (!childNode.children || childNode.children.length === 0)) {
            if (!leafChildrenByName[childNode.name]) leafChildrenByName[childNode.name] = [];
            leafChildrenByName[childNode.name].push(childNode);
          }
        });

        Object.keys(leafChildrenByName).forEach(name => {
          const group = leafChildrenByName[name];
          if (group.length > 10) {
            group.sort((a, b) => {
              const timeA = new Date(a.time || 0).getTime() || 0;
              const timeB = new Date(b.time || 0).getTime() || 0;
              return timeA - timeB;
            });

            const toDelete = group.slice(10);
            toDelete.forEach(delNode => {
              if (!currentNodes[delNode.id]) return;

              // Remove from parent's children
              if (currentNodes[node.id]) {
                currentNodes[node.id].children = currentNodes[node.id].children.filter(id => id !== delNode.id);
              }

              const descendants = getDescendants(delNode.id);
              delete currentNodes[delNode.id];
              descendants.forEach(dId => delete currentNodes[dId]);
              deletedCount += 1 + descendants.length;
            });
          }
        });
      }
    });

    if (deletedCount > 0) {
      setNodes(currentNodes);
      alert(`Đã dọn dẹp thành công ${deletedCount} tiến trình spam (vượt quá 10 tiến trình con trùng tên trên cùng một cha).`);
    } else {
      alert(`Không phát hiện tiến trình spam nào cần dọn dẹp (Mỗi Cha có dưới 10 Con trùng tên).`);
    }
  };

  const handleDetachBranch = (node) => {
    const newId = 'ws_' + Date.now();
    const newName = `🌿 ${node.name} (${node.pid})`;
    
    const newNodes = {};
    const copyNodeAndDescendants = (nId) => {
        if (!nodes[nId]) return;
        newNodes[nId] = { ...nodes[nId] };
        if (nId === node.id) {
           newNodes[nId].parents = []; // Cut ties with parent
        }
        newNodes[nId].children.forEach(childId => copyNodeAndDescendants(childId));
    };
    copyNodeAndDescendants(node.id);
    
    setWorkspaceData(prev => ({
      ...prev,
      [activeWorkspaceId]: nodes,
      [newId]: newNodes
    }));
    
    setWorkspaces(prev => [...prev, { id: newId, name: newName, isDownwardOnly: true }]);
    setActiveWorkspaceId(newId);
    setNodes(newNodes);
  };

  const handleTabSwitch = (id) => {
    if (id === activeWorkspaceId) return;
    setWorkspaceData(prev => ({ ...prev, [activeWorkspaceId]: nodes }));
    
    // Save current inputs
    workspaceInputsRef.current[activeWorkspaceId] = { name: searchProcessName, pid: searchProcessPid };
    
    setActiveWorkspaceId(id);
    const newNodes = workspaceData[id] || {};
    setNodes(newNodes);
    
    // Restore inputs
    const saved = workspaceInputsRef.current[id] || { name: '', pid: '' };
    setSearchProcessName(saved.name);
    setSearchProcessPid(saved.pid);
  };

  const handleCloseTab = (id, e) => {
    e.stopPropagation(); // prevent switching tab when clicking close
    if (id === 'root') return; // Cannot close root

    const newWorkspaces = workspaces.filter(w => w.id !== id);
    const newWorkspaceData = { ...workspaceData, [activeWorkspaceId]: nodes };
    delete newWorkspaceData[id];

    if (activeWorkspaceId === id) {
       // Switch to root if closing active tab
       setActiveWorkspaceId('root');
       const newNodes = newWorkspaceData['root'] || {};
       setNodes(newNodes);
       
       const saved = workspaceInputsRef.current['root'] || { name: '', pid: '' };
       setSearchProcessName(saved.name);
       setSearchProcessPid(saved.pid);
    } else {
       setWorkspaceData(newWorkspaceData);
    }
    setWorkspaces(newWorkspaces);
  };

  // Rendering Tree
  const renderTree = () => {
    const nodeVals = Object.values(nodes);
    if (nodeVals.length === 0) return <div style={{ color: 'var(--text-secondary)' }}>Chưa có dữ liệu cây. Nhập Process Name/PID và bấm Build để bắt đầu!</div>;

    let roots = nodeVals.filter(n => n.parents.length === 0);
    if (roots.length === 0) {
      roots = [nodeVals[0]];
    }

    // Sort roots by time
    roots.sort((a, b) => {
      const timeA = new Date(a.time || 0).getTime() || 0;
      const timeB = new Date(b.time || 0).getTime() || 0;
      return timeA - timeB;
    });

    let elements = [];
    const buildNode = (nodeId, prefix = '', isLast = true) => {
      const node = nodes[nodeId];
      if (!node) return;

      const linePrefix = prefix + (isLast ? '└── ' : '├── ');
      
      elements.push(
        <div key={`${nodeId}-${elements.length}`} className="tree-line" onMouseLeave={() => setExpandedNodeId(null)}>
          <span className="tree-prefix">{linePrefix}</span>
          <span className="tree-node-text process">
            🟢 <span className="process-name">{node.name}</span>
            <span className="process-pid"> (PID {node.pid})</span>
            {node.time && <span className="process-time"> [{node.time}]</span>}
          </span>
          {node.extra && <span className="process-extra"> [{node.extra}]</span>}
          <div className="node-actions">
            {expandedNodeId !== nodeId ? (
              <button className="action-btn expand" onClick={(e) => { e.stopPropagation(); setExpandedNodeId(nodeId); }} title="Hiện công cụ (Mở rộng)">⚙️</button>
            ) : (
              <>
                <button className="action-btn collapse" onClick={(e) => { e.stopPropagation(); setExpandedNodeId(null); }} title="Thu gọn" style={{backgroundColor: 'rgba(255, 255, 255, 0.2)'}}>✖</button>
                <button className="action-btn network" onClick={() => handleFetchNetwork(node)} title="Kéo Network (Event 3) của tiến trình này">📡</button>
                <button className="action-btn file" onClick={() => handleFetchFile(node)} title="Kéo File (Event 11) của tiến trình này">📁</button>
                <button className="action-btn" onClick={() => handleFetchDns(node)} title="Kéo DNS (Event 22) của tiến trình này" style={{backgroundColor: '#06b6d4'}}>🌐</button>
                <button className="action-btn" onClick={() => handleFetchRegistry(node)} title="Kéo Registry (Event 13) của tiến trình này" style={{backgroundColor: '#fb923c'}}>🗄️</button>
                <button className="action-btn" onClick={() => handleFetchPowerShell(node)} title="Giải mã PowerShell Script (Event 4104)" style={{backgroundColor: '#2563eb'}}>📜</button>
                <button className="action-btn query" onClick={() => handleCopyChildQuery(node)} title="Copy KQL tìm Process Con của tiến trình này">🔍</button>
                <button className="action-btn" onClick={() => handleDetachBranch(node)} title="Tách nhánh này ra một Tab mới" style={{backgroundColor: 'rgba(56, 189, 248, 0.2)'}}>✂️</button>
                <button className="action-btn delete" onClick={() => handleDeleteBranch(nodeId)} title="Xoá nhánh này">🗑️</button>
              </>
            )}
          </div>
        </div>
      );

      const childPrefix = prefix + (isLast ? '    ' : '│   ');
      const hasFiles = node.fileEvents && node.fileEvents.length > 0;
      const hasDns = node.dnsEvents && node.dnsEvents.length > 0;
      const hasReg = node.regEvents && node.regEvents.length > 0;
      const hasPs = node.psEvents && node.psEvents.length > 0;
      const hasChildren = node.children && node.children.length > 0;

      // Render Network Events
      if (node.networkEvents && node.networkEvents.length > 0) {
        node.networkEvents.forEach((netEvent, evIdx) => {
          const isLastNetwork = evIdx === node.networkEvents.length - 1;
          const useLForNetwork = !hasChildren && !hasFiles && !hasDns && !hasReg && !hasPs && isLastNetwork;
          const lineType = useLForNetwork ? '└── ' : '├── ';

          elements.push(
            <div key={`${nodeId}-net-${evIdx}`} className="tree-line">
              <span className="tree-prefix">{childPrefix + lineType}</span>
              <span className="tree-node-text network" style={{ color: '#38bdf8' }}>
                🌐 Network: [{netEvent.firstTime}{netEvent.lastTime && netEvent.lastTime !== netEvent.firstTime ? ` ➔ ${netEvent.lastTime}` : ''}] {netEvent.extraStr} <span style={{ color: '#eab308', marginLeft: '8px' }}>({netEvent.count} lần)</span>
              </span>
            </div>
          );
        });
      }

      // Render File Events
      if (node.fileEvents && node.fileEvents.length > 0) {
        node.fileEvents.forEach((fileEvent, evIdx) => {
          const isLastFile = evIdx === node.fileEvents.length - 1;
          const useLForFile = !hasChildren && !hasDns && !hasReg && !hasPs && isLastFile;
          const lineType = useLForFile ? '└── ' : '├── ';

          elements.push(
            <div key={`${nodeId}-file-${evIdx}`} className="tree-line">
              <span className="tree-prefix">{childPrefix + lineType}</span>
              <span className="tree-node-text file" style={{ color: '#f472b6' }}>
                📁 File: [{fileEvent.firstTime}{fileEvent.lastTime && fileEvent.lastTime !== fileEvent.firstTime ? ` ➔ ${fileEvent.lastTime}` : ''}] {fileEvent.extraStr} <span style={{ color: '#eab308', marginLeft: '8px' }}>({fileEvent.count} lần)</span>
              </span>
            </div>
          );
        });
      }

      // Render DNS Events
      if (node.dnsEvents && node.dnsEvents.length > 0) {
        node.dnsEvents.forEach((dnsEvent, evIdx) => {
          const isLastDns = evIdx === node.dnsEvents.length - 1;
          const useLForDns = !hasChildren && !hasReg && !hasPs && isLastDns;
          const lineType = useLForDns ? '└── ' : '├── ';

          elements.push(
            <div key={`${nodeId}-dns-${evIdx}`} className="tree-line">
              <span className="tree-prefix">{childPrefix + lineType}</span>
              <span className="tree-node-text dns" style={{ color: '#06b6d4' }}>
                🌐 DNS: [{dnsEvent.firstTime}{dnsEvent.lastTime && dnsEvent.lastTime !== dnsEvent.firstTime ? ` ➔ ${dnsEvent.lastTime}` : ''}] {dnsEvent.extraStr} <span style={{ color: '#eab308', marginLeft: '8px' }}>({dnsEvent.count} lần)</span>
              </span>
            </div>
          );
        });
      }

      // Render Registry Events
      if (node.regEvents && node.regEvents.length > 0) {
        node.regEvents.forEach((regEvent, evIdx) => {
          const isLastReg = evIdx === node.regEvents.length - 1;
          const useLForReg = !hasChildren && !hasPs && isLastReg;
          const lineType = useLForReg ? '└── ' : '├── ';

          elements.push(
            <div key={`${nodeId}-reg-${evIdx}`} className="tree-line">
              <span className="tree-prefix">{childPrefix + lineType}</span>
              <span className="tree-node-text reg" style={{ color: '#fb923c' }}>
                🗄️ Registry: [{regEvent.firstTime}{regEvent.lastTime && regEvent.lastTime !== regEvent.firstTime ? ` ➔ ${regEvent.lastTime}` : ''}] {regEvent.extraStr} <span style={{ color: '#eab308', marginLeft: '8px' }}>({regEvent.count} lần)</span>
              </span>
            </div>
          );
        });
      }

      // Render PowerShell Events
      if (node.psEvents && node.psEvents.length > 0) {
        node.psEvents.forEach((psEvent, evIdx) => {
          const isLastPs = evIdx === node.psEvents.length - 1;
          const useLForPs = !hasChildren && isLastPs;
          const lineType = useLForPs ? '└── ' : '├── ';

          elements.push(
            <div key={`${nodeId}-ps-${evIdx}`} className="tree-line">
              <span className="tree-prefix">{childPrefix + lineType}</span>
              <span className="tree-node-text ps" style={{ color: '#2563eb' }}>
                📜 PowerShell: [{psEvent.firstTime}{psEvent.lastTime && psEvent.lastTime !== psEvent.firstTime ? ` ➔ ${psEvent.lastTime}` : ''}] <span style={{ fontFamily: 'monospace', backgroundColor: 'rgba(37, 99, 235, 0.1)', padding: '2px 4px', borderRadius: '4px' }}>{psEvent.extraStr}</span> <span style={{ color: '#eab308', marginLeft: '8px' }}>({psEvent.count} lần)</span>
              </span>
            </div>
          );
        });
      }
      
      // Sort children by time before rendering
      const sortedChildren = [...node.children].sort((aId, bId) => {
        const timeA = new Date(nodes[aId]?.time || 0).getTime() || 0;
        const timeB = new Date(nodes[bId]?.time || 0).getTime() || 0;
        return timeA - timeB;
      });

      sortedChildren.forEach((childId, idx) => {
        buildNode(childId, childPrefix, idx === sortedChildren.length - 1);
      });
    };

    roots.forEach((root, idx) => {
      buildNode(root.id, '', idx === roots.length - 1);
    });

    return elements;
  };

  return (
    <div className="layout">
      {/* Sidebar Configurations */}
      <div className="sidebar">
        {!isManualMode && (
        <div className="card">
          <h2>Kết Nối API</h2>
          <div className="input-group">
            <label>Splunk URL:</label>
            <input type="text" value={apiUrl} onChange={e => setApiUrl(e.target.value)} placeholder="https://localhost:8089" />
          </div>
          <div className="api-config-grid">
            <div className="input-group">
              <label>Username:</label>
              <input type="text" value={username} onChange={e => setUsername(e.target.value)} />
            </div>
            <div className="input-group">
              <label>Password:</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} style={{width: '100%', padding: '10px 14px', backgroundColor: 'rgba(0, 0, 0, 0.4)', border: '1px solid var(--panel-border)', borderRadius: 'var(--border-radius-sm)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)'}} />
            </div>
          </div>
          
          <button type="button" onClick={handleConnectAndSync} style={{ marginBottom: connectionStatus ? '8px' : '20px', backgroundColor: '#10b981' }}>
             🔌 Kiểm tra Kết Nối & Đồng Bộ Dữ Liệu
          </button>
          {connectionStatus && (
            <div style={{
              padding: '10px',
              marginBottom: '20px',
              borderRadius: '6px',
              fontSize: '13px',
              backgroundColor: connectionStatus.type === 'success' ? 'rgba(16, 185, 129, 0.1)' : connectionStatus.type === 'error' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(255, 255, 255, 0.05)',
              color: connectionStatus.type === 'success' ? '#34d399' : connectionStatus.type === 'error' ? '#f87171' : '#9ca3af',
              border: `1px solid ${connectionStatus.type === 'success' ? 'rgba(16, 185, 129, 0.2)' : connectionStatus.type === 'error' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255, 255, 255, 0.1)'}`
            }}>
              {connectionStatus.message}
            </div>
          )}
        </div>
        )}

        <div className="card">
          <h2>Cấu Hình Index</h2>
          <div className="input-group">
            <label>Tên Index (Index Name):</label>
            <input type="text" value={indexPattern} onChange={e => setIndexPattern(e.target.value)} />
            {availableIndices.length > 0 && !isManualMode && (
              <select 
                onChange={(e) => {
                  setIndexPattern(e.target.value);
                  handleFetchFields(e.target.value);
                }} 
                style={{ width: '100%', marginTop: '10px', padding: '10px', backgroundColor: 'rgba(0,0,0,0.4)', color: 'var(--text-primary)', border: '1px solid var(--panel-border)', borderRadius: 'var(--border-radius-sm)', fontFamily: 'var(--font-mono)' }}
              >
                <option value="">-- Hoặc bấm vào đây để chọn Index --</option>
                {availableIndices.map(idx => <option key={idx} value={idx}>{idx}</option>)}
              </select>
            )}
          </div>
        </div>

        <div className="card">
          <h2 style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <span>Cấu Hình Event Fields</span>
            <span style={{ fontSize: '0.8rem', fontWeight: 'normal', color: 'var(--text-secondary)' }}>
              {indexFields.length} fields
            </span>
          </h2>

          <div onClick={() => setOpenConfig(openConfig === 'process' ? '' : 'process')} style={{ padding: '10px', backgroundColor: openConfig === 'process' ? 'rgba(255,255,255,0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid var(--panel-border)', borderBottom: openConfig === 'process' ? 'none' : '1px solid var(--panel-border)', borderRadius: openConfig === 'process' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'process' ? '0' : '10px' }}>
            <strong>⚙️ Process (Event 1, 4688)</strong><span>{openConfig === 'process' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'process' && (
            <div style={{ padding: '15px', border: '1px solid var(--panel-border)', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={eventCodeField} onChange={setEventCodeField} placeholder="event.code" suggestions={indexFields} /></div>
              <div className="input-group"><label>Parent Name:</label><AutocompleteInput value={parentNameField} onChange={setParentNameField} placeholder="process.parent.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Parent PID:</label><AutocompleteInput value={parentPidField} onChange={setParentPidField} placeholder="process.parent.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Parent Process Guid Field:</label><AutocompleteInput value={parentGuidField} onChange={setParentGuidField} placeholder="ParentProcessGuid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Guid Field:</label><AutocompleteInput value={processGuidField} onChange={setProcessGuidField} placeholder="ProcessGuid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name:</label><AutocompleteInput value={processNameField} onChange={setProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID:</label><AutocompleteInput value={processPidField} onChange={setProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (Tuỳ chọn):</label><AutocompleteInput value={extraField} onChange={setExtraField} placeholder="Ví dụ: process.command_line..." suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'network' ? '' : 'network')} style={{ padding: '10px', backgroundColor: openConfig === 'network' ? 'rgba(56, 189, 248, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #38bdf8', borderBottom: openConfig === 'network' ? 'none' : '1px solid #38bdf8', borderRadius: openConfig === 'network' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'network' ? '0' : '10px', color: '#38bdf8' }}>
            <strong>📡 Network (Event 3)</strong><span>{openConfig === 'network' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'network' && (
            <div style={{ padding: '15px', border: '1px solid #38bdf8', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={evt3CodeField} onChange={setEvt3CodeField} placeholder="event.code" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name:</label><AutocompleteInput value={evt3ProcessNameField} onChange={setEvt3ProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID:</label><AutocompleteInput value={evt3ProcessPidField} onChange={setEvt3ProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (Network data):</label><AutocompleteInput value={evt3ExtraField} onChange={setEvt3ExtraField} placeholder="destination.ip, destination.port" suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'file' ? '' : 'file')} style={{ padding: '10px', backgroundColor: openConfig === 'file' ? 'rgba(244, 114, 182, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #f472b6', borderBottom: openConfig === 'file' ? 'none' : '1px solid #f472b6', borderRadius: openConfig === 'file' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'file' ? '0' : '10px', color: '#f472b6' }}>
            <strong>📁 File (Event 11)</strong><span>{openConfig === 'file' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'file' && (
            <div style={{ padding: '15px', border: '1px solid #f472b6', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={evt11CodeField} onChange={setEvt11CodeField} placeholder="event.code" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name:</label><AutocompleteInput value={evt11ProcessNameField} onChange={setEvt11ProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID:</label><AutocompleteInput value={evt11ProcessPidField} onChange={setEvt11ProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (File data):</label><AutocompleteInput value={evt11ExtraField} onChange={setEvt11ExtraField} placeholder="file.path" suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'dns' ? '' : 'dns')} style={{ padding: '10px', backgroundColor: openConfig === 'dns' ? 'rgba(6, 182, 212, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #06b6d4', borderBottom: openConfig === 'dns' ? 'none' : '1px solid #06b6d4', borderRadius: openConfig === 'dns' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'dns' ? '0' : '10px', color: '#06b6d4' }}>
            <strong>🌐 DNS (Event 22)</strong><span>{openConfig === 'dns' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'dns' && (
            <div style={{ padding: '15px', border: '1px solid #06b6d4', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={evt22CodeField} onChange={setEvt22CodeField} placeholder="event.code" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name:</label><AutocompleteInput value={evt22ProcessNameField} onChange={setEvt22ProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID:</label><AutocompleteInput value={evt22ProcessPidField} onChange={setEvt22ProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (DNS Question):</label><AutocompleteInput value={evt22ExtraField} onChange={setEvt22ExtraField} placeholder="dns.question.name" suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'registry' ? '' : 'registry')} style={{ padding: '10px', backgroundColor: openConfig === 'registry' ? 'rgba(251, 146, 60, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #fb923c', borderBottom: openConfig === 'registry' ? 'none' : '1px solid #fb923c', borderRadius: openConfig === 'registry' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'registry' ? '0' : '10px', color: '#fb923c' }}>
            <strong>🗄️ Registry (Event 13)</strong><span>{openConfig === 'registry' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'registry' && (
            <div style={{ padding: '15px', border: '1px solid #fb923c', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={evt13CodeField} onChange={setEvt13CodeField} placeholder="event.code" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name:</label><AutocompleteInput value={evt13ProcessNameField} onChange={setEvt13ProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID:</label><AutocompleteInput value={evt13ProcessPidField} onChange={setEvt13ProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (Registry Path):</label><AutocompleteInput value={evt13ExtraField} onChange={setEvt13ExtraField} placeholder="registry.path" suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'powershell' ? '' : 'powershell')} style={{ padding: '10px', backgroundColor: openConfig === 'powershell' ? 'rgba(37, 99, 235, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #2563eb', borderBottom: openConfig === 'powershell' ? 'none' : '1px solid #2563eb', borderRadius: openConfig === 'powershell' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'powershell' ? '0' : '10px', color: '#2563eb' }}>
            <strong>📜 PowerShell (Event 4104)</strong><span>{openConfig === 'powershell' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'powershell' && (
            <div style={{ padding: '15px', border: '1px solid #2563eb', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '10px' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={evt4104CodeField} onChange={setEvt4104CodeField} placeholder="winlog.event_id" suggestions={indexFields} /></div>
              <div className="input-group"><label>Event Value:</label><input type="text" value={evt4104CodeValue} onChange={e => setEvt4104CodeValue(e.target.value)} /></div>
              <div className="input-group"><label>Process PID Field:</label><AutocompleteInput value={evt4104ProcessPidField} onChange={setEvt4104ProcessPidField} placeholder="winlog.process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Extra Field (Script Block):</label><AutocompleteInput value={evt4104ExtraField} onChange={setEvt4104ExtraField} placeholder="powershell.file.script_block_text" suggestions={indexFields} multi={true} /></div>
            </div>
          )}

          <div onClick={() => setOpenConfig(openConfig === 'logon' ? '' : 'logon')} style={{ padding: '10px', backgroundColor: openConfig === 'logon' ? 'rgba(245, 158, 11, 0.1)' : 'var(--panel-bg)', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', border: '1px solid #f59e0b', borderBottom: openConfig === 'logon' ? 'none' : '1px solid #f59e0b', borderRadius: openConfig === 'logon' ? '6px 6px 0 0' : '6px', marginBottom: openConfig === 'logon' ? '0' : '10px', color: '#f59e0b' }}>
            <strong>👤 Logon Context (4688 ➔ 4624)</strong><span>{openConfig === 'logon' ? '▼' : '▶'}</span>
          </div>
          {openConfig === 'logon' && (
            <div style={{ padding: '15px', border: '1px solid #f59e0b', borderTop: 'none', borderRadius: '0 0 6px 6px', marginBottom: '0' }}>
              <div className="input-group"><label>Event Code Field:</label><AutocompleteInput value={logonEventCodeField} onChange={setLogonEventCodeField} placeholder="winlog.event_id" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process Name Field:</label><AutocompleteInput value={logonProcessNameField} onChange={setLogonProcessNameField} placeholder="process.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Process PID Field:</label><AutocompleteInput value={logonProcessPidField} onChange={setLogonProcessPidField} placeholder="process.pid" suggestions={indexFields} /></div>
              <div className="input-group"><label>Logon ID Field:</label><AutocompleteInput value={logonIdField} onChange={setLogonIdField} placeholder="winlog.logon.id" suggestions={indexFields} /></div>
              <div className="input-group"><label>Hostname Field:</label><AutocompleteInput value={logonHostField} onChange={setLogonHostField} placeholder="host.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Source IP Field:</label><AutocompleteInput value={logonSourceIpField} onChange={setLogonSourceIpField} placeholder="source.ip" suggestions={indexFields} /></div>
              <div className="input-group"><label>User Name Field:</label><AutocompleteInput value={logonUserField} onChange={setLogonUserField} placeholder="user.name" suggestions={indexFields} /></div>
              <div className="input-group"><label>Logon Type Field:</label><AutocompleteInput value={logonTypeField} onChange={setLogonTypeField} placeholder="winlog.event_data.LogonType" suggestions={indexFields} /></div>
            </div>
          )}
        </div>
      </div>

      {/* Main Content Area */}
      <div className="main-content" style={isFullScreen ? { padding: '20px', backgroundColor: 'var(--panel-bg)', overflowY: 'auto', position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, zIndex: 9999 } : {}}>

        <div style={{ display: 'flex', borderBottom: '1px solid var(--panel-border)', marginBottom: '15px', overflowX: 'auto' }}>
          {workspaces.map(ws => (
            <div 
              key={ws.id}
              onClick={() => handleTabSwitch(ws.id)}
              style={{
                padding: '10px 20px',
                cursor: 'pointer',
                backgroundColor: activeWorkspaceId === ws.id ? 'var(--panel-bg)' : 'transparent',
                borderTop: activeWorkspaceId === ws.id ? '2px solid #10b981' : '2px solid transparent',
                borderRight: '1px solid var(--panel-border)',
                borderLeft: '1px solid var(--panel-border)',
                color: activeWorkspaceId === ws.id ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontWeight: activeWorkspaceId === ws.id ? 'bold' : 'normal',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              {ws.name}
              {ws.id !== 'root' && (
                <span 
                  onClick={(e) => handleCloseTab(ws.id, e)}
                  style={{ color: '#f87171', cursor: 'pointer', padding: '0 4px', fontSize: '16px', fontWeight: 'bold' }}
                  title="Đóng nhánh"
                >
                  ×
                </span>
              )}
            </div>
          ))}
        </div>

        <div className="card full-height">
          <h2>Tự Động Build Process Tree {activeWorkspaceId !== 'root' ? '(Chế độ Nhánh - Bỏ qua tìm Cha)' : ''}</h2>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <label className="toggle-switch">
                <input 
                  type="checkbox" 
                  checked={isCaseSensitiveMatch} 
                  onChange={(e) => setIsCaseSensitiveMatch(e.target.checked)} 
                />
                <span className="toggle-slider"></span>
              </label>
              <span style={{ fontSize: '14px', color: isCaseSensitiveMatch ? 'var(--primary)' : 'var(--text-secondary)', transition: 'color 0.3s', fontWeight: isCaseSensitiveMatch ? 'bold' : 'normal' }}>
                Phân biệt hoa thường (Case-Sensitive Match) khi gắn Event
              </span>
            </div>
          </div>
          <div className="api-config-grid" style={{ marginBottom: '15px' }}>
            <div className="input-group" style={{ marginBottom: 0 }}>
              <label>Tên Tiến trình (Process Name):</label>
              <input type="text" value={searchProcessName} onChange={e => setSearchProcessName(e.target.value)} placeholder="Ví dụ: cmd.exe" />
            </div>
            <div className="input-group" style={{ marginBottom: 0 }}>
              <label>Mã Tiến trình (Process PID):</label>
              <input type="text" value={searchProcessPid} onChange={e => setSearchProcessPid(e.target.value)} placeholder="Ví dụ: 1234" />
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button 
              onClick={handleBuild} 
              disabled={isBuilding}
              style={{ flex: 1, backgroundColor: isBuilding ? 'var(--text-secondary)' : 'var(--primary)' }}
            >
              {isBuilding ? '⏳ Đang xử lý...' : (Object.keys(nodes).length === 0 ? '🚀 Build Cây Mới' : '🔍 Auto Bulk Expand')}
            </button>
            {Object.keys(nodes).length > 0 && (
              <button 
                onClick={handleNewTab}
                disabled={isBuilding}
                style={{ flex: 0.5, backgroundColor: isBuilding ? 'var(--text-secondary)' : '#10b981' }}
              >
                ➕ Mở Tab Mới
              </button>
            )}
            {Object.keys(nodes).length > 0 && (
              <div style={{ position: 'relative' }}>
                <button 
                  onClick={() => setShowActionModal(!showActionModal)}
                  style={{ width: 'auto', backgroundColor: 'var(--panel-bg)', color: 'var(--text-primary)', border: '1px solid var(--panel-border)', padding: '10px 15px' }}
                >
                  🛠️ Các chức năng quét {showActionModal ? '▲' : '▼'}
                </button>
                {showActionModal && (
                  <div style={{ position: 'absolute', top: '100%', left: 0, marginTop: '5px', backgroundColor: 'var(--panel-bg)', border: '1px solid var(--panel-border)', borderRadius: '6px', padding: '10px', display: 'flex', flexDirection: 'column', gap: '8px', zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.5)', width: '280px' }}>
                    <button onClick={() => { handleFetchLogonContext(); setShowActionModal(false); }} disabled={isFetchingLogon} style={{ backgroundColor: '#f59e0b', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      👤 Tra cứu Logon Context
                    </button>
                    <button onClick={() => { handleBulkFetchNetwork(); setShowActionModal(false); }} disabled={isBuilding} style={{ backgroundColor: '#0ea5e9', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      📡 Quét toàn bộ Network (Event 3)
                    </button>
                    <button onClick={() => { handleBulkFetchFile(); setShowActionModal(false); }} disabled={isBuilding} style={{ backgroundColor: '#db2777', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      📁 Quét toàn bộ File (Event 11)
                    </button>
                    <button onClick={() => { handleBulkFetchDns(); setShowActionModal(false); }} disabled={isBuilding} style={{ backgroundColor: '#06b6d4', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      🌐 Quét toàn bộ DNS (Event 22)
                    </button>
                    <button onClick={() => { handleBulkFetchRegistry(); setShowActionModal(false); }} disabled={isBuilding} style={{ backgroundColor: '#fb923c', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      🗄️ Quét toàn bộ Registry (Event 13)
                    </button>
                    <button onClick={() => { handleBulkFetchPowerShell(); setShowActionModal(false); }} disabled={isBuilding} style={{ backgroundColor: '#2563eb', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      📜 Dịch PowerShell (Event 4104)
                    </button>
                    <div style={{ height: '1px', backgroundColor: 'var(--panel-border)', margin: '4px 0' }}></div>
                    <button onClick={() => { handleGeneratePrompt(); setShowActionModal(false); }} style={{ backgroundColor: '#8b5cf6', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      🤖 Tạo Prompt AI
                    </button>
                    <button onClick={() => { handlePruneSpam(); setShowActionModal(false); }} style={{ backgroundColor: '#eab308', color: '#fff', textAlign: 'left', padding: '8px 12px', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
                      ✂️ Dọn Spam & Tối ưu cây
                    </button>
                  </div>
                )}
              </div>
            )}
            <button 
              onClick={() => { setNodes({}); setLogonContext(null); setWorkspaces([{ id: 'root', name: '🌳 Cây Gốc', isDownwardOnly: false }]); setActiveWorkspaceId('root'); setWorkspaceData({'root': {}}); }} 
              style={{ width: 'auto', backgroundColor: '#da3633', marginLeft: 'auto' }}
            >
              🗑️ Xóa toàn bộ
            </button>
          </div>

          <div ref={treeContainerRef} className={`tree-container ${(isFullScreen && !document.fullscreenElement) ? 'fullscreen' : ''}`}>
            {logonContext && (
              <div style={{ backgroundColor: 'rgba(245, 158, 11, 0.1)', border: '1px solid #f59e0b', borderRadius: '6px', padding: '15px', marginBottom: '15px' }}>
                <h3 style={{ color: '#f59e0b', marginTop: 0, marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span>👤</span> Logon Context (Event 4624) của tiến trình gốc
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px', fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                  <div><strong>Logon ID:</strong> <span style={{ color: '#fcd34d' }}>{logonContext.logonId}</span></div>
                  <div><strong>User Name:</strong> <span style={{ color: '#fcd34d' }}>{logonContext.user}</span></div>
                  <div><strong>Host Name:</strong> <span style={{ color: '#fcd34d' }}>{logonContext.host}</span></div>
                  <div><strong>Source IP:</strong> <span style={{ color: '#fcd34d' }}>{logonContext.ip}</span></div>
                  <div><strong>Logon Type:</strong> <span style={{ color: '#fcd34d' }}>{logonContext.logonType}</span></div>
                </div>
              </div>
            )}
            <div className="tree-header" style={{ position: 'sticky', top: 0, right: 0, zIndex: 10, display: 'flex', justifyContent: 'flex-end', marginBottom: '10px', backgroundColor: 'var(--panel-bg)', padding: '5px' }}>
              <button 
                onClick={handleToggleFullScreen} 
                style={{ width: 'auto', backgroundColor: '#3b82f6', color: '#fff', padding: '6px 12px', fontSize: '12px', borderRadius: '4px', border: '1px solid #60a5fa', cursor: 'pointer', boxShadow: '0 2px 4px rgba(0,0,0,0.3)' }}
              >
                {isFullScreen ? '🔲 Thu nhỏ (hoặc bấm ESC)' : '🖥️ Phóng to toàn màn hình'}
              </button>
            </div>
            <div className="ascii-tree">
              {renderTree()}
            </div>
          </div>
        </div>
      </div>

      {/* Manual Input Modal */}
      {manualRequest && (() => {
        let splunkQuery = typeof manualRequest.query === 'string' ? manualRequest.query : "Dữ liệu không hợp lệ";

        const parseTabularToHits = (text, query) => {
          let hits = [];
          const setNested = (obj, path, value) => {
            if (!path) return;
            const parts = path.split('.');
            let current = obj;
            for (let i = 0; i < parts.length - 1; i++) {
              if (!current[parts[i]]) current[parts[i]] = {};
              current = current[parts[i]];
            }
            current[parts[parts.length - 1]] = value;
          };
      
          const lines = text.trim().split('\n');
          lines.forEach(line => {
            if (!line.trim()) return;
            line = line.trim();
            let parts = line.split('\t');
            if (parts.length < 3) parts = line.split(/\s{2,}/);
            if (parts.length < 3) parts = line.trim().split(/\s+/);
            
            let source = {};
            const isPid = (str) => /^\d[\d,]*$/.test((str || '').trim());
            let offset = isPid(parts[2]) ? 1 : 0;
            
            if (query.includes(`${eventCodeField}="${evt3CodeValue}"`) || query.includes(`EventCode="${evt3CodeValue}"`)) {
              if (parts.length >= 2 + offset) {
                if (offset === 1) source['@timestamp'] = parts[0].trim();
                setNested(source, eventCodeField, evt3CodeValue);
                setNested(source, evt3ProcessNameField, parts[offset].trim());
                setNested(source, evt3ProcessPidField, (parts[offset + 1] || '').replace(/,/g, '').trim());
                
                const extraCols = parts.slice(offset + 2);
                if (evt3ExtraField && extraCols.length > 0) {
                  const fields = evt3ExtraField.split(',').map(f => f.trim()).filter(f => f);
                  fields.forEach((f, idx) => {
                    if (extraCols[idx]) setNested(source, f, extraCols[idx].trim());
                  });
                  const cIdx = fields.length;
                  if (extraCols[cIdx]) setNested(source, 'count', extraCols[cIdx].replace(/,/g, '').trim());
                  if (extraCols[cIdx + 1]) setNested(source, 'firstTime', extraCols[cIdx + 1].trim());
                  if (extraCols[cIdx + 2]) setNested(source, 'lastTime', extraCols[cIdx + 2].trim());
                }
              }
            } else if (query.includes(`${eventCodeField}="${evt22CodeValue}"`) || query.includes(`EventCode="${evt22CodeValue}"`)) {
              if (parts.length >= 2 + offset) {
                if (offset === 1) source['@timestamp'] = parts[0].trim();
                setNested(source, eventCodeField, evt22CodeValue);
                setNested(source, evt22ProcessNameField, parts[offset].trim());
                setNested(source, evt22ProcessPidField, (parts[offset + 1] || '').replace(/,/g, '').trim());
                
                const extraCols = parts.slice(offset + 2);
                if (evt22ExtraField && extraCols.length > 0) {
                  const fields = evt22ExtraField.split(',').map(f => f.trim()).filter(f => f);
                  fields.forEach((f, idx) => {
                    if (extraCols[idx]) setNested(source, f, extraCols[idx].trim());
                  });
                  const cIdx = fields.length;
                  if (extraCols[cIdx]) setNested(source, 'count', extraCols[cIdx].replace(/,/g, '').trim());
                  if (extraCols[cIdx + 1]) setNested(source, 'firstTime', extraCols[cIdx + 1].trim());
                  if (extraCols[cIdx + 2]) setNested(source, 'lastTime', extraCols[cIdx + 2].trim());
                }
              }
            } else if (query.includes(`${eventCodeField}="${evt11CodeValue}"`) || query.includes(`EventCode="${evt11CodeValue}"`)) {
              if (parts.length >= 2 + offset) {
                if (offset === 1) source['@timestamp'] = parts[0].trim();
                setNested(source, eventCodeField, evt11CodeValue);
                setNested(source, evt11ProcessNameField, parts[offset].trim());
                setNested(source, evt11ProcessPidField, (parts[offset + 1] || '').replace(/,/g, '').trim());
                
                const extraCols = parts.slice(offset + 2);
                if (evt11ExtraField && extraCols.length > 0) {
                  const fields = evt11ExtraField.split(',').map(f => f.trim()).filter(f => f);
                  fields.forEach((f, idx) => {
                    if (extraCols[idx]) setNested(source, f, extraCols[idx].trim());
                  });
                  const cIdx = fields.length;
                  if (extraCols[cIdx]) setNested(source, 'count', extraCols[cIdx].replace(/,/g, '').trim());
                  if (extraCols[cIdx + 1]) setNested(source, 'firstTime', extraCols[cIdx + 1].trim());
                  if (extraCols[cIdx + 2]) setNested(source, 'lastTime', extraCols[cIdx + 2].trim());
                }
              }
            } else if (query.includes(`${evt4104CodeField}="${evt4104CodeValue}"`) || query.includes(`EventCode="${evt4104CodeValue}"`)) {
              // PowerShell (Event 4104) typically only needs PID and Script Block Text
              // Format: [Thời Gian] | [Process Name] | PID | Script Block Text
              if (parts.length >= 1 + offset) {
                if (offset === 1) source['@timestamp'] = parts[0].trim();
                setNested(source, evt4104CodeField, evt4104CodeValue);
                // PID is always at offset + 1 if Process Name is present, otherwise it might be at offset
                // Let's check if parts[offset] is PID (numeric)
                let pidIdx = isPid(parts[offset]) ? offset : (offset + 1);
                setNested(source, evt4104ProcessPidField, (parts[pidIdx] || '').replace(/,/g, '').trim());
                
                const extraCols = parts.slice(pidIdx + 1);
                if (evt4104ExtraField && extraCols.length > 0) {
                  const fields = evt4104ExtraField.split(',').map(f => f.trim()).filter(f => f);
                  fields.forEach((f, idx) => {
                    if (extraCols[idx]) setNested(source, f, extraCols[idx].trim());
                  });
                  const cIdx = fields.length;
                  if (extraCols[cIdx]) setNested(source, 'count', extraCols[cIdx].replace(/,/g, '').trim());
                  if (extraCols[cIdx + 1]) setNested(source, 'firstTime', extraCols[cIdx + 1].trim());
                  if (extraCols[cIdx + 2]) setNested(source, 'lastTime', extraCols[cIdx + 2].trim());
                }
              }
            } else if (query.includes(`${eventCodeField}="${evt13CodeValue}"`) || query.includes(`EventCode="${evt13CodeValue}"`)) {
              if (parts.length >= 2 + offset) {
                if (offset === 1) source['@timestamp'] = parts[0].trim();
                setNested(source, eventCodeField, evt13CodeValue);
                setNested(source, evt13ProcessNameField, parts[offset].trim());
                setNested(source, evt13ProcessPidField, (parts[offset + 1] || '').replace(/,/g, '').trim());
                
                const extraCols = parts.slice(offset + 2);
                if (evt13ExtraField && extraCols.length > 0) {
                  const fields = evt13ExtraField.split(',').map(f => f.trim()).filter(f => f);
                  fields.forEach((f, idx) => {
                    if (extraCols[idx]) setNested(source, f, extraCols[idx].trim());
                  });
                  const cIdx = fields.length;
                  if (extraCols[cIdx]) setNested(source, 'count', extraCols[cIdx].replace(/,/g, '').trim());
                  if (extraCols[cIdx + 1]) setNested(source, 'firstTime', extraCols[cIdx + 1].trim());
                  if (extraCols[cIdx + 2]) setNested(source, 'lastTime', extraCols[cIdx + 2].trim());
                }
              }
            } else {
               // Process Tree (Event 1 / 4688)
               let pOffset = isPid(parts[2]) ? 1 : 0;
               if (parts.length >= 6 + pOffset) {
                  if (pOffset === 1) source['@timestamp'] = parts[0].trim();
                  setNested(source, eventCodeField, '1');
                  setNested(source, parentNameField, parts[pOffset].trim());
                  setNested(source, parentPidField, parts[pOffset + 1].replace(/,/g, '').trim());
                  setNested(source, processNameField, parts[pOffset + 2].trim());
                  setNested(source, processPidField, parts[pOffset + 3].replace(/,/g, '').trim());
                  setNested(source, parentGuidField, parts[pOffset + 4].trim());
                  setNested(source, processGuidField, parts[pOffset + 5].trim());
                  
                  const extraCols = parts.slice(pOffset + 6);
                  if (extraField && extraCols.length > 0) {
                    const fields = extraField.split(',').map(f => f.trim()).filter(f => f);
                    fields.forEach((f, idx) => {
                    if (extraCols[idx]) setNested(source, f, extraCols[idx].trim());
                  });
                  const cIdx = fields.length;
                  if (extraCols[cIdx]) setNested(source, 'count', extraCols[cIdx].replace(/,/g, '').trim());
                  if (extraCols[cIdx + 1]) setNested(source, 'firstTime', extraCols[cIdx + 1].trim());
                  if (extraCols[cIdx + 2]) setNested(source, 'lastTime', extraCols[cIdx + 2].trim());
                  }
               }
            }
            
            if (Object.keys(source).length > 0) {
              hits.push({ _source: source });
            }
          });
          
          return { hits: { hits: hits } };
        };

        return (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}>
          <div style={{ backgroundColor: 'var(--panel-bg)', padding: '20px', borderRadius: '8px', width: '900px', maxWidth: '95%', maxHeight: '90vh', display: 'flex', flexDirection: 'column', border: '1px solid var(--panel-border)', boxShadow: '0 10px 25px rgba(0,0,0,0.5)' }}>
            <h3 style={{ marginTop: 0, color: '#10b981' }}>Cần dữ liệu từ Kibana (Chế độ thủ công)</h3>
            
            <ol style={{ paddingLeft: '20px', margin: '10px 0', color: 'var(--text-secondary)' }}>
              <li>Copy đoạn <strong>KQL / Lucene Query</strong> bên dưới dán vào thanh tìm kiếm Kibana Discover.</li>
              <li>Xem kết quả dạng bảng trên Kibana và <strong>Copy các cột tương ứng (hoặc JSON)</strong>.</li>
              <li>Dán dữ liệu vừa copy vào ô dưới cùng và bấm Xử lý.</li>
            </ol>

            <strong style={{ color: '#ec4899', marginTop: '10px' }}>Câu lệnh Splunk SPL (Copy/Paste vào Splunk Search):</strong>
            <button 
              onClick={() => {
                navigator.clipboard.writeText(splunkQuery);
                alert('Đã copy câu Query!');
              }}
              style={{ backgroundColor: 'rgba(255,255,255,0.1)', border: 'none', padding: '5px 10px', borderRadius: '4px', cursor: 'pointer', float: 'right', fontSize: '12px' }}
            >
              📋 Copy Query
            </button>
            <div style={{ width: '100%', minHeight: '40px', marginTop: '5px', backgroundColor: 'rgba(236, 72, 153, 0.1)', color: '#ec4899', fontFamily: 'monospace', padding: '10px', borderRadius: '4px', border: '1px solid rgba(236, 72, 153, 0.3)', wordBreak: 'break-all', fontSize: '12px' }}>
              {splunkQuery}
            </div>

            <strong style={{ marginTop: '15px' }}>Hoặc dùng Dev Tools Body (JSON):</strong>
            <button 
              onClick={() => {
                navigator.clipboard.writeText(manualRequest.query);
                alert('Đã copy JSON Body!');
              }}
              style={{ backgroundColor: 'rgba(255,255,255,0.1)', border: 'none', padding: '5px 10px', borderRadius: '4px', cursor: 'pointer', float: 'right', fontSize: '12px' }}
            >
              📋 Copy JSON
            </button>
            <textarea 
              readOnly 
              value={manualRequest.query} 
              style={{ width: '100%', height: '80px', marginTop: '5px', backgroundColor: 'rgba(0,0,0,0.2)', color: 'var(--text-secondary)', fontFamily: 'monospace', padding: '10px', borderRadius: '4px', border: '1px solid var(--panel-border)', flexShrink: 0, fontSize: '12px' }}
            />
            
            <strong style={{ marginTop: '15px' }}>Dán Kết Quả Trả Về (Dạng Bảng / CSV / JSON) vào đây:</strong>
            <p style={{ color: '#fbbf24', fontSize: '12px', margin: '5px 0' }}>
              💡 <strong>Hỗ trợ dán dạng bảng (như tool cũ):</strong><br/>
              - Build Cây: <code>Thời Gian | Parent Name | Parent PID | Process Name | Process PID | Extra (nếu có)</code><br/>
              - Quét Network: <code>Process Name | PID | Source IP | Dest IP | Extra</code><br/>
              - Quét File: <code>Thời Gian | Process Name | PID | File Path | Extra</code><br/>
              - Quét DNS: <code>Process Name | PID | DNS Question | DNS Answer | Extra</code>
            </p>
            <textarea 
              value={manualResponseInput}
              onChange={(e) => setManualResponseInput(e.target.value)}
              placeholder="Dán dữ liệu dạng cột (Tab/Space) hoặc Response JSON vào đây..."
              style={{ width: '100%', flexGrow: 1, minHeight: '120px', marginTop: '5px', backgroundColor: 'rgba(0,0,0,0.3)', color: 'var(--text-primary)', fontFamily: 'monospace', padding: '10px', borderRadius: '4px', border: '1px solid var(--panel-border)' }}
            />
            
            <div style={{ display: 'flex', gap: '10px', marginTop: '20px', justifyContent: 'flex-end' }}>
              <button onClick={() => { setManualRequest(null); manualRequest.onReject(new Error('Người dùng đã hủy')); }} style={{ backgroundColor: 'transparent', border: '1px solid var(--panel-border)' }}>
                ❌ Hủy bỏ
              </button>
              <button 
                onClick={() => {
                  try {
                    let parsed;
                    const inputStr = manualResponseInput.trim();
                    if (inputStr.startsWith('{')) {
                       parsed = JSON.parse(inputStr);
                    } else {
                       parsed = parseTabularToHits(inputStr, splunkQuery);
                    }
                    manualRequest.onResolve(parsed);
                    setManualResponseInput('');
                  } catch (e) {
                    alert('Lỗi xử lý dữ liệu: Vui lòng kiểm tra lại cấu trúc dữ liệu vừa dán!');
                  }
                }} 
                style={{ backgroundColor: '#10b981' }}
              >
                ✅ Xử lý kết quả
              </button>
            </div>
          </div>
        </div>
        );
      })()}
    </div>
  );
}

export default SplunkApiView;
