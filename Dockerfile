  FROM alpine
  RUN echo "KEBAP run25" && sleep 60 && echo "KEBAP done"
  CMD ["sleep", "infinity"]
