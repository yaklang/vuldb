package dbm

import (
	"fmt"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	PostgresPassword      = "awesome-vuldb"
	PostgresDatabaseName  = "vuldb"
	PostgresHost          = "127.0.0.1"
	PostgresPort          = 5433
	PostgresUser          = "vuldb-user"
	PostgresContainerName = "vuldb-postgres"
)

func GetPostgresParams() (string, error) {
	name := PostgresDatabaseName
	pwd := PostgresPassword

	return fmt.Sprintf("host=%s port=%v user=%s dbname=%s password=%s sslmode=disable",
		PostgresHost, PostgresPort, PostgresUser,
		name, pwd,
	), nil
}

func StartPostgres() error {
	param, err := GetPostgresParams()
	if err != nil {
		return errors.Errorf("parsing postgres params failed: %s", err)
	}

	password := PostgresPassword
	dbname := PostgresDatabaseName

	logrus.Info("detecting database connecting...")
	d, err := gorm.Open("postgres", param)
	if err == nil {
		logrus.Info("detected exsited database.")
		_ = d.Close()
		return nil
	}

	logrus.Infof("no existed database or open database failed: %s", err)

	logrus.Info("try to start a database...")

	_ = exec.Command("docker", "kill", PostgresContainerName).Run()

	/*
		// docker run -it --rm --name={PostgresContainerName} -e "" --net=host postgres

		POSTGRES_PASSWORD
		POSTGRES_USER
		POSTGRES_DB
	*/
	cmd := exec.Command(
		"docker",
		"run", "-d", // "--rm",

		// setting container name
		"--name", PostgresContainerName,

		// setting envs
		"-e", fmt.Sprintf("POSTGRES_PASSWORD=%s", password),
		"-e", fmt.Sprintf("POSTGRES_USER=%s", PostgresUser),
		"-e", fmt.Sprintf("POSTGRES_DB=%s", dbname),

		// publish ports
		"-p", fmt.Sprintf("%s:%v:5432", PostgresHost, PostgresPort),

		"postgres",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		logrus.Debugf("run %s %s failed: %s", cmd.Path, strings.Join(cmd.Args, " "), err)
		return errors.Errorf("run postgres database failed: %s", err)
	}

	ticker := time.Tick(1 * time.Second)
	count := 0
	for {
		select {
		case <-ticker:
			count++
			conn, err := gorm.Open("postgres", param)
			//conn, err := net.Dial("tcp", "127.0.0.1:5432")
			if err != nil {
				logrus.Warningf("try %v times... waiting for the postgres starting up...", err)
				continue
			}

			_ = conn.Close()
			return nil
		}
	}
}
