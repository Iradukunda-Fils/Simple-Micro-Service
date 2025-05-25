# Stage: Final image
FROM nginx:1.28.0-bookworm


LABEL maintainer="Iradukunda Fils <iradukundafils1.com>"
LABEL description="Highly-optimized Nginx image for Django microservices"

# Create non-root user
RUN groupadd -r appgroup && \
    useradd -r -g appgroup -m -d /home/appuser -s /usr/sbin/nologin appuser

# Set working directory
WORKDIR /etc/nginx

# Copy custom Nginx configuration (make sure it doesn't use port 80 if user is non-root)
COPY --chown=appuser:appgroup ./nginx.conf ./nginx.conf

# Expose port (use 8080 if non-root)
EXPOSE 80


CMD ["nginx", "-g", "daemon off;"]

