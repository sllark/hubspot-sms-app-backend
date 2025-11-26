FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package.json yarn.lock* package-lock.json* ./

# Install dependencies
RUN npm install --production

# Copy application files
COPY . .

# Expose port (Fly.io will set PORT env var)
EXPOSE 3000

# Start the application
CMD ["node", "index.js"]
