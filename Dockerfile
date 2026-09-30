  FROM alpine
  RUN echo "KEBAP run 3" && sleep 60 && echo "KEBAP done"
  CMD ["sleep", "infinity"]
