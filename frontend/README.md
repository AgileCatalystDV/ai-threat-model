# AI Threat Model Frontend

React + TypeScript frontend for the AI Threat Model tool.

## Setup

```bash
npm install
```

## Development

```bash
npm run dev
```

The frontend will run on http://localhost:3000 and proxy API requests to http://localhost:8000.

## Build

```bash
npm run build
```

## Environment Variables

Create a `.env` file:

```
VITE_API_URL=http://localhost:8000
```

## Features

- **Threat Model List**: View all threat models
- **Threat Model Editor**: Visual editor with React Flow
- **Vision Analysis**: Upload diagrams/images and extract components automatically
- **Threat Analysis**: Run threat detection on models
