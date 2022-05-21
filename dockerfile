FROM gcc:10.3
COPY . /app
WORKDIR /app/
RUN make
CMD ["bash"]
