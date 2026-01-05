# Local MongoDB Setup Guide

## Quick Start

### Option 1: Using MongoDB Community Edition (Recommended)

1. **Download MongoDB Community Edition:**
   - Visit: https://www.mongodb.com/try/download/community
   - Download for Windows
   - Install with default settings

2. **Start MongoDB Service:**
   ```powershell
   # MongoDB usually starts automatically as a Windows service
   # If not, start it manually:
   net start MongoDB
   ```

3. **Verify MongoDB is Running:**
   ```powershell
   # Check if MongoDB is listening on port 27017
   netstat -an | findstr 27017
   ```

### Option 2: Using MongoDB via Docker

```powershell
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

### Option 3: Using MongoDB Atlas (Cloud - Current Setup)

If you prefer to keep using MongoDB Atlas, update `.env`:
```
MONGO_URL=mongodb+srv://4al22is018_db_user:CodeTech2004@cluster0.hfweelr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0
```

## Current Configuration

The project is now configured to use **local MongoDB** by default:
- **Database Name:** `secure-transfer`
- **Connection String:** `mongodb://localhost:27017/secure-transfer`

## Verify Connection

After starting MongoDB, restart your backend server:
```powershell
npm run server
```

You should see: `MongoDB connected to local MongoDB`

## Troubleshooting

- **Port 27017 in use:** MongoDB is already running
- **Connection refused:** MongoDB is not running - start the service
- **Authentication failed:** Check MongoDB configuration or use Atlas instead

