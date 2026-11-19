# المرحلة 1: بناء تطبيق React
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# الواجهة تتصل بالخادم عبر Nginx على نفس العنوان (/api) فلا حاجة لـ CORS
ARG VITE_API_URL=/api
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# المرحلة 2: تقديم الملفات عبر Nginx
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
