FROM nginx:alpine

COPY index.html dashboard.css dashboard.js snyk_vulnerability_dataset.csv /usr/share/nginx/html/
RUN chmod 644 /usr/share/nginx/html/*

EXPOSE 80
