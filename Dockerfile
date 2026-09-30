  FROM alpine
  RUN echo "KEBAP run 2" && sleep 60 && echo "KEBAP done"
  CMD ["sleep", "infinity"]
