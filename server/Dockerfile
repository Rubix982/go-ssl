# Use the official Nginx image from the Docker Hub
FROM nginx:latest

RUN mkdir -p /etc/nginx/ssl
RUN apt-get update && apt-get install -y apache2-utils
# Create .htpasswd file for basic auth
RUN htpasswd -bc /etc/nginx/.htpasswd saif privaci

# Copy the Nginx configuration file
COPY nginx.conf /etc/nginx/nginx.conf

# Copy the SSL certificates and HTML files
COPY etc/nginx/certs /etc/nginx/certs
COPY etc/nginx/html /etc/nginx/html

# Rename and add files
ADD etc/nginx/certs/fullchain19.pem /etc/nginx/ssl/public.crt
ADD etc/nginx/certs/privkey19.pem /etc/nginx/ssl/private.key
ADD etc/nginx/certs/root_ca.pem /etc/nginx/ssl/client_ca.pem
ADD ./nginx.conf /etc/nginx/conf.d/default.conf

# Expose ports
EXPOSE 80 443 8080

# Start Nginx when the container launches
CMD ["nginx", "-g", "daemon off;"]
