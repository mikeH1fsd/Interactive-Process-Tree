import React, { useState, useEffect } from 'react';
import AutocompleteInput from './AutocompleteInput';

function ElasticApiView() {
  const [apiUrl, setApiUrl] = useState('http://10.48.144.79:9200');
  const [username, setUsername] = useState('elastic');
  const [password, setPassword] = useState('elastic');
  const [indexPattern, setIndexPattern] = useState('winlogbeat-*');

  // Fields Mapping
  const [eventCodeField, setEventCodeField] = useState('event.code');
  const [parentNameField, setParentNameField] = useState('process.parent.name');
  const [parentPidField, setParentPidField] = useState('process.parent.pid');
  const [processNameField, setProcessNameField] = useState('process.name');
  const [processPidField, setProcessPidField] = useState('process.pid');

  // Search
  const [searchProcessName, setSearchProcessName] = useState('');
  const [searchProcessPid, setSearchProcessPid] = useState('');

  // Event 3 Config
  const [evt3CodeField, setEvt3CodeField] = useState('event.code');
  const [evt3CodeValue, setEvt3CodeValue] = useState('3');
  const [evt3ProcessNameField, setEvt3ProcessNameField] = useState('process.name');
  const [evt3ProcessPidField, setEvt3ProcessPidField] = useState('process.pid');
  const [evt3ExtraField, setEvt3ExtraField] = useState('destination.ip, destination.port');

  // Event 11 Config
  const [evt11CodeField, setEvt11CodeField] = useState('event.code');
  const [evt11CodeValue, setEvt11CodeValue] = useState('11');
  const [evt11ProcessNameField, setEvt11ProcessNameField] = useState('process.name');
  const [evt11ProcessPidField, setEvt11ProcessPidField] = useState('process.pid');
  const [evt11ExtraField, setEvt11ExtraField] = useState('file.path');

  // Tree State
  const [nodes, setNodes] = useState({});
  const [isBuilding, setIsBuilding] = useState(false);
  const [availableIndices, setAvailableIndices] = useState([]);
  const [indexFields, setIndexFields] = useState([
    '@timestamp', 'event.code', 'process.name', 'process.pid', 'process.parent.name', 'process.parent.pid'
  ]);
  const [extraField, setExtraField] = useState('');
  const [isFullScreen, setIsFullScreen] = useState(false);

  useEffect(() => {
    const handleFullScreenChange = () => {
      setIsFullScreen(!!document.fullscreenElement);
    };
    document.addEventListener('fullscreenchange', handleFullScreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullScreenChange);
  }, []);

  const handleToggleFullScreen = () => {
    if (!document.fullscreenElement) {
      const elem = document.getElementById('elastic-tree-container');
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
      const response = await fetch(`/elastic_api/${pattern}/_mapping`, {
        headers: { 
          'Authorization': authHeader,
          'x-target-url': apiUrl
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
    try {
      const authHeader = 'Basic ' + btoa(`${username}:${password}`);
      const response = await fetch(`/elastic_api/_cat/indices?format=json&h=index`, {
        headers: { 
          'Authorization': authHeader,
          'x-target-url': apiUrl
        }
      });
      if (response.ok) {
        const data = await response.json();
        // Filter out system indices starting with dot
        const indices = data.map(d => d.index).filter(i => !i.startsWith('.'));
        setAvailableIndices(indices);
        
        // Auto fetch fields for the default/current index pattern
        await handleFetchFields(indexPattern);
        
        alert(`✅ Kết nối thành công! Đã tải danh sách Index và đồng bộ Fields.`);
      } else {
        alert('❌ Lỗi kết nối (Sai thông tin đăng nhập hoặc URL): ' + response.statusText);
      }
    } catch (e) {
      alert('❌ Lỗi mạng khi kết nối tới Elastic: ' + e.message);
    }
  };

  // Parse result hits to update nodes
  const processHits = (hits) => {
    let currentNodes = { ...nodes };
    hits.forEach(hit => {
      const source = hit._source;
      const getNested = (obj, path) => path.split('.').reduce((acc, part) => acc && acc[part], obj);
      
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

        const processId = `${pName}_${pPid}`;
        const parentId = `${parentName}_${parentPid}`;

        if (!currentNodes[processId]) {
          currentNodes[processId] = { id: processId, name: pName, pid: pPid, time: time, parents: [], children: [], extra: extraStr, fileEvents: [], regEvents: [], dnsEvents: [], networkEvents: [] };
        } else {
          if (time) currentNodes[processId].time = time;
          if (extraStr) currentNodes[processId].extra = extraStr;
        }
        if (!currentNodes[parentId]) {
          currentNodes[parentId] = { id: parentId, name: parentName, pid: parentPid, time: '', parents: [], children: [], extra: '', fileEvents: [], regEvents: [], dnsEvents: [], networkEvents: [] };
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
      let conditions = [`${eventCodeField}: "1"`];
      if (searchProcessName) conditions.push(`${processNameField}: "${searchProcessName}"`);
      if (searchProcessPid) conditions.push(`${processPidField}: "${searchProcessPid}"`);
      queryStr = conditions.join(" AND ");
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
          const excludeList = spamNames.map(name => `"${name}"`).join(" OR ");
          return ` AND NOT ${processNameField}: (${excludeList})`;
        }
        return "";
      };

      const rootQueries = roots.map(root => {
        const excludeChildren = getExclusionStr(root);
        // Root searches for its own parents OR (its children AND NOT spam children)
        return `((${processNameField}: "${root.name}" AND ${processPidField}: "${root.pid}") OR (${parentNameField}: "${root.name}" AND ${parentPidField}: "${root.pid}"${excludeChildren}))`;
      });
      
      const leafQueries = leaves.map(leaf => {
        const excludeChildren = getExclusionStr(leaf);
        return `(${parentNameField}: "${leaf.name}" AND ${parentPidField}: "${leaf.pid}"${excludeChildren})`;
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
      queryStr = `(${eventCodeField}: "1") AND (${queries.join(" OR ")})`;
    }

    try {
      const authHeader = 'Basic ' + btoa(`${username}:${password}`);
      const response = await fetch(`/elastic_api/${indexPattern}/_search`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': authHeader,
          'x-target-url': apiUrl
        },
        body: JSON.stringify({
          query: {
            query_string: {
              query: queryStr
            }
          },
          size: 500,
          sort: [
            { "@timestamp": { "order": "asc", "unmapped_type": "boolean" } }
          ]
        })
      });

      if (!response.ok) {
        throw new Error(`API Error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      if (data.hits && data.hits.hits) {
        processHits(data.hits.hits);
      }
    } catch (error) {
      alert("Lỗi khi gọi API: " + error.message + "\nNếu bị lỗi Failed to fetch, có thể do cấu hình CORS trên Elastic.");
    } finally {
      setIsBuilding(false);
    }
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
    const query = `${parentNameField}: "${node.name}" AND ${parentPidField}: "${node.pid}"`;
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
        let baseStr = `(${evt3CodeField}: "${evt3CodeValue}") AND (${evt3ProcessNameField}: "${node.name}") AND (${evt3ProcessPidField}: "${node.pid}")`;
        if (excludes.length > 0) {
          baseStr += ` AND (${excludes.join(" AND ")})`;
        }
        const response = await fetch(`/elastic_api/${indexPattern}/_search`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': authHeader,
            'x-target-url': apiUrl
          },
          body: JSON.stringify({
            query: { query_string: { query: baseStr } },
            size: 200, // Size limit
            sort: [ { "@timestamp": { "order": "asc", "unmapped_type": "boolean" } } ]
          })
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

            if (!allEventsMap[extraStr]) {
              allEventsMap[extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: 1 };
            } else {
              allEventsMap[extraStr].count++;
              allEventsMap[extraStr].lastTime = time;
            }
          });

          // If we hit the limit, there might be spam blocking other events
          if (hits.length === 200) {
            const spamGroups = Object.values(allEventsMap).filter(g => g.count >= 50);
            spamGroups.forEach(g => {
              const conditions = Object.entries(g.rawFields).map(([k, v]) => `${k}: "${v}"`);
              if (conditions.length > 0) {
                const excludeStr = `NOT (${conditions.join(" AND ")})`;
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
        let baseStr = `(${evt11CodeField}: "${evt11CodeValue}") AND (${evt11ProcessNameField}: "${node.name}") AND (${evt11ProcessPidField}: "${node.pid}")`;
        if (excludes.length > 0) {
          baseStr += ` AND (${excludes.join(" AND ")})`;
        }
        const response = await fetch(`/elastic_api/${indexPattern}/_search`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': authHeader,
            'x-target-url': apiUrl
          },
          body: JSON.stringify({
            query: { query_string: { query: baseStr } },
            size: 200,
            sort: [ { "@timestamp": { "order": "asc", "unmapped_type": "boolean" } } ]
          })
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

            if (!allEventsMap[extraStr]) {
              allEventsMap[extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: 1 };
            } else {
              allEventsMap[extraStr].count++;
              allEventsMap[extraStr].lastTime = time;
            }
          });

          if (hits.length === 200) {
            const spamGroups = Object.values(allEventsMap).filter(g => g.count >= 50);
            spamGroups.forEach(g => {
              const conditions = Object.entries(g.rawFields).map(([k, v]) => `${k}: "${v}"`);
              if (conditions.length > 0) {
                const excludeStr = `NOT (${conditions.join(" AND ")})`;
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

  const handleBulkFetchNetwork = async () => {
    setIsBuilding(true);
    const nodeVals = Object.values(nodes);
    if (nodeVals.length === 0) {
      setIsBuilding(false);
      return;
    }

    const nodeQueries = nodeVals.map(n => `(${evt3ProcessNameField}: "${n.name}" AND ${evt3ProcessPidField}: "${n.pid}")`);
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
          let queryStr = `(${evt3CodeField}: "${evt3CodeValue}") AND (${chunk.join(" OR ")})`;
          if (excludeList.length > 0) {
            queryStr += ` AND (${excludeList.join(" AND ")})`;
          }

          const authHeader = 'Basic ' + btoa(`${username}:${password}`);
          const response = await fetch(`/elastic_api/${indexPattern}/_search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': authHeader, 'x-target-url': apiUrl },
            body: JSON.stringify({
              query: { query_string: { query: queryStr } },
              size: 5000,
              sort: [ { "@timestamp": { "order": "asc", "unmapped_type": "boolean" } } ]
            })
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
              const processId = `${pName}_${pPid}`;

              if (currentNodes[processId]) {
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

                if (!bulkEventsMap[processId]) bulkEventsMap[processId] = {};
                if (!bulkEventsMap[processId][extraStr]) {
                  bulkEventsMap[processId][extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: 1 };
                } else {
                  bulkEventsMap[processId][extraStr].count++;
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
                    const excludeStr = `NOT (${conditions.join(" AND ")})`;
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

    const nodeQueries = nodeVals.map(n => `(${evt11ProcessNameField}: "${n.name}" AND ${evt11ProcessPidField}: "${n.pid}")`);
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
          let queryStr = `(${evt11CodeField}: "${evt11CodeValue}") AND (${chunk.join(" OR ")})`;
          if (excludeList.length > 0) {
            queryStr += ` AND (${excludeList.join(" AND ")})`;
          }

          const authHeader = 'Basic ' + btoa(`${username}:${password}`);
          const response = await fetch(`/elastic_api/${indexPattern}/_search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': authHeader, 'x-target-url': apiUrl },
            body: JSON.stringify({
              query: { query_string: { query: queryStr } },
              size: 5000,
              sort: [ { "@timestamp": { "order": "asc", "unmapped_type": "boolean" } } ]
            })
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
              const processId = `${pName}_${pPid}`;

              if (currentNodes[processId]) {
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

                if (!bulkEventsMap[processId]) bulkEventsMap[processId] = {};
                if (!bulkEventsMap[processId][extraStr]) {
                  bulkEventsMap[processId][extraStr] = { extraStr, rawFields, firstTime: time, lastTime: time, count: 1 };
                } else {
                  bulkEventsMap[processId][extraStr].count++;
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
                    const excludeStr = `NOT (${conditions.join(" AND ")})`;
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
        <div key={`${nodeId}-${elements.length}`} className="tree-line">
          <span className="tree-prefix">{linePrefix}</span>
          <span className="tree-node-text process">
            🟢 <span className="process-name">{node.name}</span>
            <span className="process-pid"> (PID {node.pid})</span>
            {node.time && <span className="process-time"> [{node.time}]</span>}
          </span>
          {node.extra && <span className="process-extra"> [{node.extra}]</span>}
          <div className="node-actions">
            <button className="action-btn network" onClick={() => handleFetchNetwork(node)} title="Kéo Network (Event 3) của tiến trình này">📡</button>
            <button className="action-btn file" onClick={() => handleFetchFile(node)} title="Kéo File (Event 11) của tiến trình này">📁</button>
            <button className="action-btn query" onClick={() => handleCopyChildQuery(node)} title="Copy KQL tìm Process Con của tiến trình này">🔍</button>
            <button className="action-btn delete" onClick={() => handleDeleteBranch(nodeId)} title="Xoá nhánh này">🗑️</button>
          </div>
        </div>
      );

      const childPrefix = prefix + (isLast ? '    ' : '│   ');
      const hasFiles = node.fileEvents && node.fileEvents.length > 0;
      const hasChildren = node.children && node.children.length > 0;

      // Render Network Events
      if (node.networkEvents && node.networkEvents.length > 0) {
        node.networkEvents.forEach((netEvent, evIdx) => {
          const isLastNetwork = evIdx === node.networkEvents.length - 1;
          const useLForNetwork = !hasChildren && !hasFiles && isLastNetwork;
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
          const useLForFile = !hasChildren && isLastFile;
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
        <div className="card">
          <h2>Kết Nối API</h2>
          <div className="input-group">
            <label>Elastic URL:</label>
            <input type="text" value={apiUrl} onChange={e => setApiUrl(e.target.value)} placeholder="http://10.48.144.79:9200" />
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
          
          <button type="button" onClick={handleConnectAndSync} style={{ marginBottom: '20px', backgroundColor: '#10b981' }}>
             🔌 Kiểm tra Kết Nối & Đồng Bộ Dữ Liệu
          </button>

          <div className="input-group">
            <label>Index Pattern (Gõ tự do hoặc chọn ở dưới):</label>
            <input type="text" value={indexPattern} onChange={e => setIndexPattern(e.target.value)} />
            {availableIndices.length > 0 && (
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
          <h2 style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span>Cấu Hình Fields</span>
            <span style={{ fontSize: '0.8rem', fontWeight: 'normal', color: 'var(--text-secondary)' }}>
              {indexFields.length} fields đã tải
            </span>
          </h2>
          <div className="input-group">
            <label>Event Code Field:</label>
            <AutocompleteInput value={eventCodeField} onChange={setEventCodeField} placeholder="event.code" suggestions={indexFields} />
          </div>
          <div className="input-group">
            <label>Parent Name:</label>
            <AutocompleteInput value={parentNameField} onChange={setParentNameField} placeholder="process.parent.name" suggestions={indexFields} />
          </div>
          <div className="input-group">
            <label>Parent PID:</label>
            <AutocompleteInput value={parentPidField} onChange={setParentPidField} placeholder="process.parent.pid" suggestions={indexFields} />
          </div>
          <div className="input-group">
            <label>Process Name:</label>
            <AutocompleteInput value={processNameField} onChange={setProcessNameField} placeholder="process.name" suggestions={indexFields} />
          </div>
          <div className="input-group">
            <label>Process PID:</label>
            <AutocompleteInput value={processPidField} onChange={setProcessPidField} placeholder="process.pid" suggestions={indexFields} />
          </div>
          <div className="input-group">
            <label>Extra Field (Tuỳ chọn - Hiện thêm thông tin):</label>
            <AutocompleteInput value={extraField} onChange={setExtraField} placeholder="Ví dụ: process.command_line, user.name..." suggestions={indexFields} multi={true} />
          </div>

          <h3 style={{ marginTop: '20px', marginBottom: '10px', fontSize: '1.1rem', color: '#38bdf8' }}>Cấu Hình Network (Event 3)</h3>
          <div className="input-group">
            <label>Event Code Field:</label>
            <AutocompleteInput value={evt3CodeField} onChange={setEvt3CodeField} placeholder="event.code" suggestions={indexFields} />
          </div>
          <div className="input-group">
            <label>Process Name:</label>
            <AutocompleteInput value={evt3ProcessNameField} onChange={setEvt3ProcessNameField} placeholder="process.name" suggestions={indexFields} />
          </div>
          <div className="input-group">
            <label>Process PID:</label>
            <AutocompleteInput value={evt3ProcessPidField} onChange={setEvt3ProcessPidField} placeholder="process.pid" suggestions={indexFields} />
          </div>
          <div className="input-group">
            <label>Extra Field (Network data):</label>
            <AutocompleteInput value={evt3ExtraField} onChange={setEvt3ExtraField} placeholder="destination.ip, destination.port" suggestions={indexFields} multi={true} />
          </div>

          <h3 style={{ marginTop: '20px', marginBottom: '10px', fontSize: '1.1rem', color: '#f472b6' }}>Cấu Hình File (Event 11)</h3>
          <div className="input-group">
            <label>Event Code Field:</label>
            <AutocompleteInput value={evt11CodeField} onChange={setEvt11CodeField} placeholder="event.code" suggestions={indexFields} />
          </div>
          <div className="input-group">
            <label>Process Name:</label>
            <AutocompleteInput value={evt11ProcessNameField} onChange={setEvt11ProcessNameField} placeholder="process.name" suggestions={indexFields} />
          </div>
          <div className="input-group">
            <label>Process PID:</label>
            <AutocompleteInput value={evt11ProcessPidField} onChange={setEvt11ProcessPidField} placeholder="process.pid" suggestions={indexFields} />
          </div>
          <div className="input-group">
            <label>Extra Field (File data):</label>
            <AutocompleteInput value={evt11ExtraField} onChange={setEvt11ExtraField} placeholder="file.path, file.name" suggestions={indexFields} multi={true} />
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="main-content">
        <div className="card full-height">
          <h2>Tự Động Build Process Tree</h2>
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
              <>
                <button 
                  onClick={handleBulkFetchNetwork} 
                  disabled={isBuilding}
                  style={{ width: 'auto', backgroundColor: isBuilding ? 'var(--text-secondary)' : '#0ea5e9', color: '#fff' }}
                  title="Kéo toàn bộ Network (Event 3) cho tất cả Process trên cây"
                >
                  📡 Quét Network
                </button>
                <button 
                  onClick={handleBulkFetchFile} 
                  disabled={isBuilding}
                  style={{ width: 'auto', backgroundColor: isBuilding ? 'var(--text-secondary)' : '#db2777', color: '#fff' }}
                  title="Kéo toàn bộ File (Event 11) cho tất cả Process trên cây"
                >
                  📁 Quét File
                </button>
              </>
            )}
            <button 
              onClick={handlePruneSpam} 
              style={{ width: 'auto', backgroundColor: '#eab308', color: '#000' }}
              title="Cắt tỉa các Process con trùng tên (Chỉ giữ lại 10 Process đầu tiên)"
            >
              ✂️ Dọn Spam
            </button>
            <button 
              onClick={() => setNodes({})} 
              style={{ width: 'auto', backgroundColor: '#da3633' }}
            >
              🗑️ Xóa toàn bộ
            </button>
          </div>

          <div id="elastic-tree-container" className={`tree-container ${isFullScreen ? 'fullscreen' : ''}`}>
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
    </div>
  );
}

export default ElasticApiView;
