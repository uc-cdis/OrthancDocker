REPO=gen3-orthanc
TAG_NAME=fix_orthanc_perf

docker build . -t $REPO
docker tag $REPO quay.io/cdis/$REPO:$TAG_NAME
docker push quay.io/cdis/$REPO:$TAG_NAME