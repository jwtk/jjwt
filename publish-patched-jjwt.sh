./mvnw install -Dmaven.test.skip=true

./mvnw deploy:deploy-file -Durl=http://ir-nexus-gcp.inf-impact.net:8081/repository/thirdparty \
                       -DrepositoryId=thirdparty \
                       -Dfile=impl/target/jjwt-impl-0.12.5-IMPACT-PATCHED.jar \
                       -DpomFile=impl/pom.xml \
                       -DgroupId=io.jsonwebtoken \
                       -DartifactId=jjwt-impl \
                       -Dversion=0.12.5-IMPACT-PATCHED \
                       -Dpackaging=jar \
                       -DgeneratePom=false