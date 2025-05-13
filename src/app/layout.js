export const metadata = {
  title: 'DataSaurus - Forensic File Input',
  description: 'Upload and manage digital evidence files for forensic analysis',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, padding: 0, backgroundColor: '#f9f9f9' }}>
        {children}
      </body>
    </html>
  );
}
