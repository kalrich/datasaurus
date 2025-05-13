'use client';

import React, { useState, useRef } from 'react';

export default function DataSaurusApp() {
  const [files, setFiles] = useState([]);
  const [processing, setProcessing] = useState(false);
  const [isDragActive, setIsDragActive] = useState(false);
  const fileInputRef = useRef(null);
  const [custodyLog, setCustodyLog] = useState([]);
  
  // Hex viewer state
  const [hexViewOpen, setHexViewOpen] = useState(false);
  const [hexViewFile, setHexViewFile] = useState(null);
  const [hexData, setHexData] = useState('');
  const [hexOffset, setHexOffset] = useState(0);
  const hexChunkSize = 256; // How many bytes to display at once
  const [fileSignature, setFileSignature] = useState({ name: '', hex: '' });
  const [searchTerm, setSearchTerm] = useState('');
  const [searchType, setSearchType] = useState('hex');
  const [searchResults, setSearchResults] = useState([]);
  const [currentSearchResult, setCurrentSearchResult] = useState(-1);

  // Common file signatures
  const FILE_SIGNATURES = [
    { hex: 'FF D8 FF', name: 'JPEG image' },
    { hex: '89 50 4E 47', name: 'PNG image' },
    { hex: '47 49 46 38', name: 'GIF image' },
    { hex: '25 50 44 46', name: 'PDF document' },
    { hex: '50 4B 03 04', name: 'ZIP archive/Office document' },
    { hex: '4D 5A', name: 'Windows executable (MZ)' },
    { hex: '7F 45 4C 46', name: 'ELF executable' },
    { hex: '1F 8B', name: 'GZIP archive' },
    { hex: '42 5A 68', name: 'BZIP2 archive' },
    { hex: '37 7A BC AF', name: '7-Zip archive' },
    { hex: '52 61 72 21', name: 'RAR archive' },
    { hex: '75 73 74 61 72', name: 'TAR archive' },
    { hex: '4D 53 43 46', name: 'Microsoft CAB' },
    { hex: '49 53 63 28', name: 'InstallShield CAB' },
    { hex: 'D0 CF 11 E0', name: 'Microsoft Office (OLE)' },
    { hex: '0D 44 4F 43', name: 'DOC file' },
    { hex: 'FF FE', name: 'UTF-16 LE text' },
    { hex: 'FE FF', name: 'UTF-16 BE text' },
    { hex: 'EF BB BF', name: 'UTF-8 text with BOM' },
    { hex: '53 51 4C 69', name: 'SQLite database' },
    { hex: '00 01 00 00', name: 'TrueType font' },
    { hex: '4C 00 00 00', name: 'Windows Event Log' },
    { hex: 'CD 21', name: 'Windows/DOS executable' },
    { hex: '43 57 53', name: 'Adobe Flash' },
    { hex: '46 4C 56', name: 'Flash video' },
    { hex: '49 44 33', name: 'MP3 audio (with ID3)' },
    { hex: 'FF FB', name: 'MP3 audio' },
    { hex: '66 74 79 70', name: 'MP4 video' },
    { hex: '52 49 46 46', name: 'RIFF container (AVI/WAV)' },
    { hex: '4F 67 67 53', name: 'OGG container' },
    { hex: '38 42 50 53', name: 'Photoshop document' },
    { hex: '45 86 00 00', name: 'VMware disk' },
    { hex: '65 87 78 56', name: 'QEMU QCOW disk image' },
    { hex: '63 82 01 00', name: 'DHCP packet (pcap)' },
    { hex: 'D4 C3 B2 A1', name: 'Packet capture (pcap)' },
    { hex: '4E 45 53 1A', name: 'NES ROM' },
    { hex: '75 73 74 61 72 00 30 30', name: 'TAR archive' }
  ];

  // Acceptable file types
  const acceptableFileTypes = [
    // Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.csv', '.html', '.htm', '.xml',
    // Images
    '.jpg', '.jpeg', '.png', '.gif', '.tif', '.tiff', '.bmp',
    // Emails
    '.pst', '.ost', '.msg', '.eml', '.mbox',
    // Archives
    '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz',
    // Disk Images
    '.dd', '.raw', '.img', '.e01', '.ex01', '.vmdk', '.vhd',
    // Logs
    '.evtx', '.log',
    // Databases
    '.sqlite', '.db', '.mdb', '.accdb',
    // Executables
    '.exe', '.dll', '.ps1', '.bat', '.sh'
  ];

  // Log forensic actions for chain of custody
  function logForensicAction(action, details) {
    const entry = {
      timestamp: new Date().toISOString(),
      action,
      details,
      user: 'Forensic Investigator' // In a real app, this would be the authenticated user
    };
    
    setCustodyLog(prev => [entry, ...prev]);
  }

  // Handle drag events
  function handleDragEnter(e) {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(true);
  }

  function handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
  }

  function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragActive) setIsDragActive(true);
  }

  function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      // Create a fake event object with the files
      handleFileUpload({ target: { files: e.dataTransfer.files } });
    }
  }

  // Handle file upload
  function handleFileUpload(event) {
    setProcessing(true);
    
    // Get files from input
    const selectedFiles = Array.from(event.target.files);
    
    // Log the action
    logForensicAction('Evidence Files Uploaded', `${selectedFiles.length} file(s) selected`);
    
    // Filter for acceptable file types if needed
    const validFiles = selectedFiles.filter(file => {
      const extension = '.' + file.name.split('.').pop().toLowerCase();
      return acceptableFileTypes.includes(extension);
    });
    
    // Alert if some files were invalid
    if (validFiles.length < selectedFiles.length) {
      const skippedCount = selectedFiles.length - validFiles.length;
      alert(`${skippedCount} file(s) were ignored because they are not supported file types.`);
      logForensicAction('Files Rejected', `${skippedCount} file(s) rejected due to unsupported file types`);
    }
    
    // Create file objects with forensic properties
    const forensicFiles = validFiles.map(file => ({
      name: file.name,
      size: file.size,
      type: file.type,
      lastModified: file.lastModified,
      path: URL.createObjectURL(file),
      // The actual file object for hex reading
      fileObject: file,
      // Properties that would normally be filled by other nodes
      hash: { md5: null, sha1: null, sha256: null },
      metadata: null,
      signature: null
    }));
    
    // Simulate processing delay
    setTimeout(() => {
      setFiles([...files, ...forensicFiles]);
      setProcessing(false);
      
      // Log successful upload
      if (forensicFiles.length > 0) {
        logForensicAction('Evidence Files Processed', `${forensicFiles.length} file(s) successfully processed`);
      }
    }, 1000);
  }

  // Remove a file
  function removeFile(index) {
    const removedFile = files[index];
    logForensicAction('Evidence File Removed', `Removed file: ${removedFile.name}`);
    
    const newFiles = [...files];
    
    // Release the object URL to avoid memory leaks
    URL.revokeObjectURL(newFiles[index].path);
    
    newFiles.splice(index, 1);
    setFiles(newFiles);
  }

  // Format file size for display
  function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
  
  // Read file as hex
  async function readFileAsHex(file, offset, length) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      const blob = file.slice(offset, offset + length);
      
      reader.onload = (event) => {
        const buffer = event.target.result;
        const bytes = new Uint8Array(buffer);
        let hexString = '';
        let asciiString = '';
        
        // Format the hex view with 16 bytes per line
        for (let i = 0; i < bytes.length; i += 16) {
          // Offset
          hexString += `${(offset + i).toString(16).padStart(8, '0')}: `;
          
          // Hex values
          for (let j = 0; j < 16; j++) {
            if (i + j < bytes.length) {
              const byte = bytes[i + j];
              hexString += `${byte.toString(16).padStart(2, '0')} `;
              
              // Add extra space after 8 bytes for readability
              if (j === 7) {
                hexString += ' ';
              }
              
              // ASCII representation
              if (byte >= 32 && byte <= 126) {
                asciiString += String.fromCharCode(byte);
              } else {
                asciiString += '.';
              }
            } else {
              hexString += '   ';
              if (j === 7) {
                hexString += ' ';
              }
              asciiString += ' ';
            }
          }
          
          // Add ASCII representation
          hexString += ` |${asciiString}|\n`;
          asciiString = '';
        }
        
        resolve(hexString);
      };
      
      reader.readAsArrayBuffer(blob);
    });
  }

  // Function to open the hex viewer for a file
  async function openHexViewer(file) {
    setHexViewFile(file);
    setHexOffset(0);
    setHexViewOpen(true);
    setSearchResults([]);
    setCurrentSearchResult(-1);
    setSearchTerm('');
    
    logForensicAction('Hex View Opened', `Opened hex viewer for file: ${file.name}`);
    
    // Read first 16 bytes for signature detection
    const reader = new FileReader();
    const headerBlob = file.fileObject.slice(0, 16);
    
    reader.onload = (event) => {
      const buffer = event.target.result;
      const bytes = new Uint8Array(buffer);
      const headerHex = Array.from(bytes.slice(0, 16))
        .map(b => b.toString(16).padStart(2, '0').toUpperCase())
        .join(' ');
      
      // Check against signatures
      const detectedSignature = FILE_SIGNATURES.find(sig => {
        const sigBytes = sig.hex.split(' ');
        for (let i = 0; i < sigBytes.length; i++) {
          if (bytes[i] !== parseInt(sigBytes[i], 16)) {
            return false;
          }
        }
        return true;
      });
      
      if (detectedSignature) {
        setFileSignature({
          name: detectedSignature.name,
          hex: detectedSignature.hex
        });
        logForensicAction('File Signature Detected', `Detected: ${detectedSignature.name} (${detectedSignature.hex})`);
      } else {
        setFileSignature({
          name: 'Unknown',
          hex: headerHex.substring(0, 11) + '...'
        });
        logForensicAction('File Signature Unknown', `Could not identify file signature for ${file.name}`);
      }
    };
    
    reader.readAsArrayBuffer(headerBlob);
    
    const initialHex = await readFileAsHex(file.fileObject, 0, hexChunkSize);
    setHexData(initialHex);
  }

  // Read file as binary
  async function readFileAsBinary(file, offset, length) {
    return new Promise((resolve) => {
      const reader = new FileReader();
      const blob = file.slice(offset, offset + length);
      
      reader.onload = (event) => {
        const buffer = event.target.result;
        const bytes = new Uint8Array(buffer);
        resolve(bytes);
      };
      
      reader.readAsArrayBuffer(blob);
    });
  }

  // Search for hex or text pattern
  async function searchHex() {
    if (!searchTerm.trim() || !hexViewFile) return;
    
    logForensicAction('Hex Search', `Searching for ${searchType === 'hex' ? 'hex pattern' : 'text'}: "${searchTerm}"`);
    
    const results = [];
    const chunkSize = 1024 * 1024; // 1MB chunks for processing
    let offset = 0;
    
    while (offset < hexViewFile.size) {
      const chunk = await readFileAsBinary(hexViewFile.fileObject, offset, Math.min(chunkSize, hexViewFile.size - offset));
      
      if (searchType === 'hex') {
        // Convert search term to byte array
        const searchBytes = searchTerm.trim().split(/\s+/).map(hex => parseInt(hex, 16));
        
        // Search for byte pattern
        for (let i = 0; i < chunk.length - searchBytes.length + 1; i++) {
          let found = true;
          for (let j = 0; j < searchBytes.length; j++) {
            if (chunk[i + j] !== searchBytes[j]) {
              found = false;
              break;
            }
          }
          if (found) {
            results.push(offset + i);
          }
        }
      } else {
        // Text search
        const searchStr = searchTerm.trim();
        const textDecoder = new TextDecoder();
        const text = textDecoder.decode(chunk);
        
        let idx = text.indexOf(searchStr);
        while (idx !== -1) {
          results.push(offset + idx);
          idx = text.indexOf(searchStr, idx + 1);
        }
      }
      
      offset += chunkSize;
    }
    
    setSearchResults(results);
    if (results.length > 0) {
      setCurrentSearchResult(0);
      navigateToOffset(results[0]);
      logForensicAction('Hex Search Results', `Found ${results.length} matches`);
    } else {
      alert('No matches found');
      logForensicAction('Hex Search Results', 'No matches found');
    }
  }

  // Navigate to specific offset
  function navigateToOffset(offset) {
    // Navigate to the chunk containing the offset
    const alignedOffset = Math.floor(offset / hexChunkSize) * hexChunkSize;
    setHexOffset(alignedOffset);
    readFileAsHex(hexViewFile.fileObject, alignedOffset, hexChunkSize).then(setHexData);
  }

  // Navigate between search results
  function navigateSearchResults(direction) {
    if (searchResults.length === 0) return;
    
    let newIndex = currentSearchResult;
    
    if (direction === 'next') {
      newIndex = (currentSearchResult + 1) % searchResults.length;
    } else if (direction === 'prev') {
      newIndex = (currentSearchResult - 1 + searchResults.length) % searchResults.length;
    }
    
    setCurrentSearchResult(newIndex);
    navigateToOffset(searchResults[newIndex]);
  }

  // Function to navigate in the hex viewer
  async function navigateHex(direction) {
    if (!hexViewFile) return;
    
    let newOffset = hexOffset;
    
    if (direction === 'next') {
      newOffset = Math.min(hexViewFile.size - hexChunkSize, hexOffset + hexChunkSize);
    } else if (direction === 'prev') {
      newOffset = Math.max(0, hexOffset - hexChunkSize);
    } else if (direction === 'start') {
      newOffset = 0;
    } else if (direction === 'end') {
      newOffset = Math.max(0, hexViewFile.size - hexChunkSize);
    }
    
    if (newOffset !== hexOffset) {
      setHexOffset(newOffset);
      const newHexData = await readFileAsHex(hexViewFile.fileObject, newOffset, hexChunkSize);
      setHexData(newHexData);
    }
  }

  // Calculate SHA-256 hash of a file
  async function calculateFileHash(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = async (event) => {
        try {
          const buffer = event.target.result;
          const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
          resolve(hashHex);
        } catch (error) {
          reject(error);
        }
      };
      
      reader.onerror = () => reject(reader.error);
      
      reader.readAsArrayBuffer(file);
    });
  }

  // Calculate hash for a specific file
  async function calculateHash(index) {
    const file = files[index];
    
    if (!file) return;
    
    try {
      logForensicAction('Hash Calculation Started', `Calculating SHA-256 hash for ${file.name}`);
      
      const hashValue = await calculateFileHash(file.fileObject);
      
      // Update the file object with the hash
      const newFiles = [...files];
      newFiles[index] = {
        ...newFiles[index],
        hash: {
          ...newFiles[index].hash,
          sha256: hashValue
        }
      };
      
      setFiles(newFiles);
      
      logForensicAction('Hash Calculation Completed', `SHA-256: ${hashValue}`);
      
      alert(`SHA-256 Hash: ${hashValue}`);
    } catch (error) {
      console.error('Hash calculation error:', error);
      logForensicAction('Hash Calculation Failed', `Error: ${error.message}`);
      alert('Failed to calculate hash: ' + error.message);
    }
  }

  // Export evidence and chain of custody log
  function exportForensicData() {
    // Prepare data for export
    const exportData = {
      evidenceFiles: files.map(file => ({
        name: file.name,
        size: file.size,
        type: file.type,
        lastModified: file.lastModified,
        hash: file.hash
      })),
      chainOfCustody: custodyLog,
      exportDate: new Date().toISOString(),
      caseInformation: {
        investigator: 'Forensic Investigator',
        exportTimestamp: new Date().toISOString()
      }
    };
    
    // Convert to JSON
    const jsonData = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    // Create download link
    const link = document.createElement('a');
    link.href = url;
    link.download = `forensic-evidence-export-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    logForensicAction('Evidence Data Exported', `Exported ${files.length} files and chain of custody log`);
  }

  return (
    <div style={{ fontFamily: 'Arial, sans-serif', maxWidth: '1200px', margin: '0 auto', padding: '20px' }}>
      <header style={{ marginBottom: '20px' }}>
        <h1 style={{ display: 'flex', alignItems: 'center' }}>
          <span style={{ marginRight: '10px', fontSize: '1.5em' }}>🦕</span> 
          DataSaurus - Forensic File Input Node
        </h1>
        <p>Upload and manage digital evidence files for forensic analysis</p>
      </header>

      <main>
        <div style={{ 
          border: '2px solid #4caf50', 
          borderRadius: '8px', 
          overflow: 'hidden',
          backgroundColor: 'white',
          boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
        }}>
          {/* Node Header */}
          <div style={{ backgroundColor: '#4caf50', color: 'white', padding: '10px', display: 'flex', alignItems: 'center' }}>
            <span style={{ fontSize: '1.5em', marginRight: '10px' }}>🦕</span>
            <div>
              <div style={{ fontWeight: 'bold' }}>DataSaurus</div>
              <div style={{ fontSize: '0.8em' }}>File Input Node</div>
            </div>
          </div>
          
          {/* Node Content */}
          <div style={{ padding: '15px' }}>
            <div 
              style={{ 
                border: '2px dashed #ccc', 
                borderRadius: '5px', 
                padding: '20px', 
                textAlign: 'center',
                backgroundColor: isDragActive ? '#e8f5e9' : processing ? '#f1f8e9' : 'transparent',
                transition: 'background-color 0.3s'
              }}
              onDragEnter={handleDragEnter}
              onDragLeave={handleDragLeave}
              onDragOver={handleDragOver}
              onDrop={handleDrop}
            >
              <input
                type="file"
                multiple
                ref={fileInputRef}
                onChange={handleFileUpload}
                style={{ display: 'none' }}
                accept={acceptableFileTypes.join(',')}
              />
              
              {processing ? (
                <div>
                  <div style={{ marginBottom: '10px' }}>Processing files...</div>
                  <div style={{ 
                    width: '50%', 
                    height: '4px', 
                    backgroundColor: '#e8f5e9', 
                    margin: '0 auto',
                    borderRadius: '2px',
                    overflow: 'hidden'
                  }}>
                    <div style={{ 
                      width: '50%', 
                      height: '100%', 
                      backgroundColor: '#4caf50',
                      animation: 'pulse 1.5s infinite ease-in-out',
                      borderRadius: '2px'
                    }}></div>
                  </div>
                  <style jsx>{`
                    @keyframes pulse {
                      0% { transform: translateX(-100%); }
                      100% { transform: translateX(200%); }
                    }
                  `}</style>
                </div>
              ) : (
                <div>
                  <button
                    onClick={() => fileInputRef.current.click()}
                    style={{
                      backgroundColor: '#4caf50',
                      color: 'white',
                      border: 'none',
                      padding: '10px 20px',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      fontSize: '14px',
                      fontWeight: 'bold'
                    }}
                  >
                    Upload Evidence Files
                  </button>
                  <div style={{ marginTop: '10px', color: '#666', fontSize: '13px' }}>
                    Drag and drop evidence files here, or click to select
                  </div>
                </div>
              )}
            </div>
            
            {/* File List */}
            {files.length > 0 && (
              <div style={{ marginTop: '20px' }}>
                <div style={{ 
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '8px'
                }}>
                  <div style={{ fontSize: '14px', fontWeight: 'bold' }}>
                    {files.length} Evidence Item{files.length !== 1 && 's'}:
                  </div>
                  <button
                    onClick={exportForensicData}
                    style={{
                      backgroundColor: '#2196f3',
                      color: 'white',
                      border: 'none',
                      padding: '5px 10px',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      fontSize: '12px'
                    }}
                  >
                    Export Data
                  </button>
                </div>
                <div style={{ maxHeight: '200px', overflowY: 'auto', border: '1px solid #e0e0e0', borderRadius: '4px' }}>
                  {files.map((file, index) => (
                    <div 
                      key={index} 
                      style={{ 
                        fontSize: '13px', 
                        backgroundColor: index % 2 === 0 ? '#f9f9f9' : 'white', 
                        padding: '8px 10px', 
                        display: 'flex',
                        justifyContent: 'space-between',
                        borderBottom: index < files.length - 1 ? '1px solid #eee' : 'none'
                      }}
                    >
                      <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                        {file.name}
                      </div>
                      <div style={{ color: '#666', marginLeft: '10px', marginRight: '10px' }}>
                        {formatFileSize(file.size)}
                      </div>
                      <div>
                        <button
                          onClick={() => calculateHash(index)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: '#9c27b0',
                            cursor: 'pointer',
                            fontSize: '12px',
                            marginRight: '10px'
                          }}
                          title="Calculate SHA-256 Hash"
                        >
                          Hash
                        </button>
                        <button
                          onClick={() => openHexViewer(file)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: '#4caf50',
                            cursor: 'pointer',
                            fontSize: '12px',
                            marginRight: '10px'
                          }}
                          title="View File in Hex Editor"
                        >
                          Hex
                        </button>
                        <button
                          onClick={() => removeFile(index)}
                          style={{
                            background: 'none',
                            border: 'none',
                            color: '#f44336',
                            cursor: 'pointer',
                            fontSize: '16px',
                            fontWeight: 'bold',
                            padding: '0 6px'
                          }}
                          title="Remove File"
                        >
                          ×
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
          
          {/* Node Status */}
          <div style={{ 
            backgroundColor: '#f5f5f5', 
            padding: '10px', 
            borderTop: '1px solid #e0e0e0',
            fontSize: '13px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <span>
              {files.length > 0 
                ? `${files.length} file${files.length !== 1 ? 's' : ''} ready` 
                : 'No files uploaded'}
            </span>
            {files.length > 0 && (
              <span style={{ 
                backgroundColor: '#e8f5e9', 
                color: '#4caf50', 
                padding: '3px 8px',
                borderRadius: '12px',
                fontSize: '11px',
                fontWeight: 'bold'
              }}>
                Ready to process
              </span>
            )}
          </div>
        </div>
        
        {/* Evidence Properties */}
        {files.length > 0 && (
          <div style={{ marginTop: '30px' }}>
            <h2>Evidence Properties</h2>
            <p>
              This shows the property structure of the first evidence file, which would normally be used by other nodes
              in a complete ForensicOS implementation:
            </p>
            <pre style={{ 
              backgroundColor: '#f5f5f5', 
              padding: '15px', 
              borderRadius: '5px',
              overflow: 'auto',
              fontSize: '13px'
            }}>
              {JSON.stringify({...files[0], fileObject: '[File Object]'}, null, 2)}
            </pre>
          </div>
        )}
        
        {/* Chain of Custody Log */}
        {custodyLog.length > 0 && (
          <div style={{ marginTop: '30px' }}>
            <h2>Chain of Custody Log</h2>
            <p>
              This log records all actions performed on the evidence files to maintain chain of custody:
            </p>
            <div style={{ 
              maxHeight: '200px', 
              overflowY: 'auto', 
              border: '1px solid #e0e0e0', 
              borderRadius: '4px',
              fontSize: '13px'
            }}>
              {custodyLog.map((entry, index) => (
                <div 
                  key={index} 
                  style={{ 
                    padding: '8px 10px', 
                    borderBottom: index < custodyLog.length - 1 ? '1px solid #eee' : 'none',
                    backgroundColor: index % 2 === 0 ? '#f9f9f9' : 'white',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontWeight: 'bold' }}>{entry.action}</span>
                    <span style={{ color: '#666' }}>{new Date(entry.timestamp).toLocaleString()}</span>
                  </div>
                  <div style={{ marginTop: '4px' }}>{entry.details}</div>
                  <div style={{ fontSize: '11px', color: '#888', marginTop: '2px' }}>User: {entry.user}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      <footer style={{ marginTop: '30px', textAlign: 'center', color: '#666', fontSize: '14px' }}>
        <p>ForensicOS - Digital Forensics Platform with Comprehensive Chain of Custody</p>
      </footer>

      {/* Hex Viewer Modal */}
      {hexViewOpen && hexViewFile && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000
        }}>
          <div style={{
            backgroundColor: 'white',
            borderRadius: '8px',
            boxShadow: '0 4px 20px rgba(0, 0, 0, 0.2)',
            width: '90%',
            maxWidth: '1000px',
            maxHeight: '90vh',
            display: 'flex',
            flexDirection: 'column'
          }}>
            {/* Modal Header */}
            <div style={{
              padding: '15px',
              borderBottom: '1px solid #eee',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <h3 style={{ margin: 0 }}>
                Hex View: {hexViewFile.name}
              </h3>
              <button
                onClick={() => setHexViewOpen(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  fontSize: '20px',
                  cursor: 'pointer'
                }}
              >
                ×
              </button>
            </div>
            
            {/* File Statistics */}
            <div style={{
              padding: '10px 15px',
              backgroundColor: '#f8f8f8',
              borderBottom: '1px solid #eee',
              display: 'flex',
              flexWrap: 'wrap',
              gap: '20px',
              fontSize: '13px'
            }}>
              <div>
                <strong>File Size:</strong> {formatFileSize(hexViewFile.size)}
              </div>
              <div>
                <strong>MIME Type:</strong> {hexViewFile.type || 'Unknown'}
              </div>
              <div>
                <strong>Last Modified:</strong> {new Date(hexViewFile.lastModified).toLocaleString()}
              </div>
            </div>
            
            {/* File Signature */}
            <div style={{
              padding: '0 15px',
              marginBottom: '10px',
              marginTop: '10px'
            }}>
              <div style={{
                backgroundColor: '#f0f7ff',
                padding: '8px 12px',
                borderRadius: '4px',
                fontSize: '13px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div>
                  <strong>File Signature:</strong> {fileSignature.name || 'Unknown'}
                </div>
                <div>
                  <strong>Hex:</strong> <code>{fileSignature.hex || 'N/A'}</code>
                </div>
              </div>
            </div>
            
            {/* Search Bar */}
            <div style={{
              padding: '10px 15px 0',
              display: 'flex',
              gap: '10px'
            }}>
              <input
                type="text"
                placeholder="Search for hex (e.g. FF D8) or text..."
                style={{
                  padding: '5px 10px',
                  border: '1px solid #ccc',
                  borderRadius: '4px',
                  flex: 1
                }}
                onChange={(e) => setSearchTerm(e.target.value)}
                value={searchTerm}
                onKeyPress={(e) => e.key === 'Enter' && searchHex()}
              />
              <select
                style={{
                  padding: '5px 10px',
                  border: '1px solid #ccc',
                  borderRadius: '4px'
                }}
                onChange={(e) => setSearchType(e.target.value)}
                value={searchType}
              >
                <option value="hex">Hex</option>
                <option value="text">Text</option>
              </select>
              <button
                onClick={searchHex}
                style={{
                  padding: '5px 15px',
                  backgroundColor: '#4caf50',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Search
              </button>
            </div>
            
            {/* Search Results Navigation */}
            {searchResults.length > 0 && (
              <div style={{
                padding: '5px 15px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '13px'
              }}>
                <div>
                  Showing result {currentSearchResult + 1} of {searchResults.length}
                </div>
                <div>
                  <button
                    onClick={() => navigateSearchResults('prev')}
                    style={{
                      padding: '3px 8px',
                      marginRight: '5px',
                      backgroundColor: '#9c27b0',
                      color: 'white',
                      border: 'none',
                      borderRadius: '3px',
                      cursor: 'pointer',
                      fontSize: '12px'
                    }}
                  >
                    Previous Match
                  </button>
                  <button
                    onClick={() => navigateSearchResults('next')}
                    style={{
                      padding: '3px 8px',
                      backgroundColor: '#9c27b0',
                      color: 'white',
                      border: 'none',
                      borderRadius: '3px',
                      cursor: 'pointer',
                      fontSize: '12px'
                    }}
                  >
                    Next Match
                  </button>
                </div>
              </div>
            )}
            
            {/* Hex Display */}
            <div style={{
              padding: '15px',
              overflowY: 'auto',
              flex: 1
            }}>
              <div style={{
                fontFamily: 'monospace',
                whiteSpace: 'pre',
                fontSize: '14px',
                backgroundColor: '#f5f5f5',
                padding: '10px',
                borderRadius: '4px',
                overflow: 'auto'
              }}>
                {hexData}
              </div>
            </div>
            
            {/* Navigation Controls */}
            <div style={{
              padding: '15px',
              borderTop: '1px solid #eee',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <div style={{ fontSize: '13px' }}>
                Showing bytes {hexOffset} to {Math.min(hexOffset + hexChunkSize, hexViewFile.size)} of {hexViewFile.size}
              </div>
              <div>
                <button
                  onClick={() => navigateHex('start')}
                  disabled={hexOffset === 0}
                  style={{
                    padding: '5px 10px',
                    marginRight: '5px',
                    backgroundColor: hexOffset === 0 ? '#e0e0e0' : '#4caf50',
                    color: 'white',
                    border: 'none',
                    borderRadius: '3px',
                    cursor: hexOffset === 0 ? 'default' : 'pointer'
                  }}
                >
                  Start
                </button>
                <button
                  onClick={() => navigateHex('prev')}
                  disabled={hexOffset === 0}
                  style={{
                    padding: '5px 10px',
                    marginRight: '5px',
                    backgroundColor: hexOffset === 0 ? '#e0e0e0' : '#4caf50',
                    color: 'white',
                    border: 'none',
                    borderRadius: '3px',
                    cursor: hexOffset === 0 ? 'default' : 'pointer'
                  }}
                >
                  Previous
                </button>
                <button
                  onClick={() => navigateHex('next')}
                  disabled={hexOffset + hexChunkSize >= hexViewFile.size}
                  style={{
                    padding: '5px 10px',
                    marginRight: '5px',
                    backgroundColor: hexOffset + hexChunkSize >= hexViewFile.size ? '#e0e0e0' : '#4caf50',
                    color: 'white',
                    border: 'none',
                    borderRadius: '3px',
                    cursor: hexOffset + hexChunkSize >= hexViewFile.size ? 'default' : 'pointer'
                  }}
                >
                  Next
                </button>
                <button
                  onClick={() => navigateHex('end')}
                  disabled={hexOffset + hexChunkSize >= hexViewFile.size}
                  style={{
                    padding: '5px 10px',
                    backgroundColor: hexOffset + hexChunkSize >= hexViewFile.size ? '#e0e0e0' : '#4caf50',
                    color: 'white',
                    border: 'none',
                    borderRadius: '3px',
                    cursor: hexOffset + hexChunkSize >= hexViewFile.size ? 'default' : 'pointer'
                  }}
                >
                  End
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}