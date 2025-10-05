FROM node:20-slim

WORKDIR /app

# Ensure the Vite proxy inside the container points to the backend service
ENV VITE_API_BASE=http://backend:8000

COPY package.json /app/
COPY vite.config.ts /app/
COPY tailwind.config.js /app/
COPY postcss.config.js /app/
COPY index.html /app/
RUN npm install

COPY src /app/src

EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
