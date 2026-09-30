FROM alpine
RUN echo "KEBAP start" && sleep 60 && echo "KEBAP done"
CMD ["sleep", "infinity"]
