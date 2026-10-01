  FROM alpine
  RUN echo "KEBAP run 5" && sleep 60 && echo "KEBAP done"
  CMD ["sleep", "infinity"]
