  FROM alpine
  RUN echo "KEBAP run 4" && sleep 60 && echo "KEBAP done"
  CMD ["sleep", "infinity"]
