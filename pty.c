/*

  su password
			by stanley zhu

 */



# include <stdio.h> 
# include <stdlib.h> 
# include <string.h> 
# include <unistd.h> 
# include <sys/types.h> 
# include <linux/limits.h> 
# include <pty.h> 


enum program_return_codes {
    RETURN_NOERROR,
    RETURN_INVALID_ARGUMENTS,
    RETURN_CONFLICTING_ARGUMENTS,
    RETURN_RUNTIME_ERROR,
    RETURN_PARSE_ERRROR,
    RETURN_INCORRECT_PASSWORD,
    RETURN_HOST_KEY_UNKNOWN,
    RETURN_HOST_KEY_CHANGED,
	RETURN_SOMTHING_WRONG,
};


struct {
    enum { PWT_STDIN, PWT_PASS } pwtype;


	const char *password;

	const char *pwprompt;
    int verbose;
} args;

#define PASSWORD_PROMPT "assword"

char command[PATH_MAX];


static void show_help()
{
    printf("Usage:  [-f|-d|-p|-e] [-hV] command parameters\n"
	    
	    
	    "   -p password   Provide password as argument (security unwise)\n"
	    
	    "   With no parameters - password will be taken from stdin\n\n"
            "   -P prompt     Which string should supass search for to detect a password prompt\n"
            "   -v            Be verbose about what you're doing\n"
	    "   -h            Show help (this screen)\n"
	    "   -V            Print version information\n"
	    "At most one of -p should be used\n");
}





static int parse_options(int argc,char *argv[])
{
	int error = -1;
	int opt;
	args.pwtype = PWT_STDIN;
	while((opt=getopt(argc,argv,"+p:P:hVv"))!=-1 && error==-1)
	{
		switch(opt)
		{
		case 'p':
			args.pwtype = PWT_PASS;
			args.password = strdup(optarg);
			{
				int i;
				for(i=0;optarg[i]!='\0';i++)
					optarg[i]='z';
			}
			break;
		case 'P':
			args.pwprompt = optarg;
			break;
		case 'v':
			args.verbose++;
			break;
		case '?':
		case ':':
			error = RETURN_INVALID_ARGUMENTS;
			break;
		case 'V':
			printf("su password taken tools\n\n"
                    "(C) made by stanely zhu.\n"
		    "This program is free software, and can be distributed under the terms of the GPL\n"
		    "See the COPYING file for more information.\n"
                    "\n"
                    "Using assword as the default password prompt indicator.\n");
			exit(0);
			break;
		case 'h':
			error=RETURN_NOERROR;
			break;

		}
		
	}

	if( error>=0 )
		return -(error+1);
    else
		return optind;

}

int match( const char *reference, const char *buffer, ssize_t bufsize, int state )
{
    // This is a highly simplisic implementation. It's good enough for matching "Password: ", though.
    int i;
    for( i=0;reference[state]!='\0' && i<bufsize; ++i ) {
	if( reference[state]==buffer[i] )
	    state++;
	else {
	    state=0;
	    if( reference[state]==buffer[i] )
		state++;
	}
    }

    return state;
}

//find string in string, return the first start location or -1 if can not find
int StringFind(const char *pSrc, const char *pDst)
{
	int i, j;
	for (i=0; pSrc[i]!='\0'; i++)
	{
		if(pSrc[i]!=pDst[0])
			continue;		
		j = 0;
		while(pDst[j]!='\0' && pSrc[i+j]!='\0')
		{
			j++;
			if(pDst[j]!=pSrc[i+j])
			break;
		}
		if(pDst[j]=='\0')
			return i;
	}
	return -1;
}


void write_pass_fd( int srcfd, int dstfd )
{

    int done=0;
    memset(command,PATH_MAX,0);
    while( !done ) {
	char buffer[PATH_MAX];
	memset(buffer,PATH_MAX,0);
	int i;
	int numread=read( srcfd, buffer, sizeof(buffer) );
	
	for(i=0;i<strlen(buffer);i++)
	{
		if(buffer[i]!='\xa')
		{
			command[i]=buffer[i];
		}
		else
		{
			command[i]='\0';
		}
	}

	done=(numread<1);
	for( i=0; i<numread && !done; ++i ) {
	    if( buffer[i]!='\n' )
		write( dstfd, buffer+i, 1 );
	    else
		done=1;
	}
    }

    write( dstfd, "\n", 1 );
}

void write_pass( int fd )
{
    switch( args.pwtype ) {
    case PWT_STDIN:
		write_pass_fd( STDIN_FILENO, fd );
		break;
    case PWT_PASS:
		write( fd, args.password, strlen( args.password ) );
		write( fd, "\n", 1 );
		break;
    }
}


int isCommand(const char *buffer, const char *command)
{
 

	int flag =0;

	int tmpflag=0;

	int i=0;
	for(i=0;i<strlen(command);i++)
	{
		if(buffer[i]==command[i])
		{
			tmpflag=1;
		}
		else
		{
			tmpflag=0;
			break;
		}
	}
	if((tmpflag==1)&&(buffer[i]=='\x0d')&&(buffer[i+1]=='\x0a'))
	{
		flag=1;
	}

	return flag;

}

int handleoutput(int fd)
{
	static int state1;
	static int firsttime = 1;
	static const char *compare1=PASSWORD_PROMPT;
	static int prevmatch=0;	
	char buffer[80];

	int ret=0;

	if( args.pwprompt ) 
	{
        compare1 = args.pwprompt;
    }

	if( args.verbose && firsttime ) {
        firsttime=0;
        fprintf(stderr, "SUPASS searching for password prompt using match \"%s\"\n", compare1);
    }
	

	int numread=read(fd, buffer, sizeof(buffer)-1 );
	if(numread <=0)
	{
		return 0;
	}
	
	
	
	if(args.verbose)
	{
		fprintf(stderr, "supass read: %s:%d",buffer,strlen(buffer));
	}
	
	//state1 = match(compare1,buffer,numread,state1);
	int flag = StringFind(buffer,compare1);

	if( flag != -1 ) 
	{
		if(!prevmatch)
		{

			if( args.verbose )
                	fprintf(stderr, "SUPASS detected prompt. Sending password.\n");

			write_pass( fd );
			prevmatch=1; // if aleady in su shell , another assword will be ignore
		}
	}
	else
	{
		const char *tempbuf;
		tempbuf=buffer;
		if( args.verbose )
		{
	                fprintf(stderr, "not passwd,show whatever in pty!");
		}
	/*
		int i=0;
		for(i=0;i<strlen(command);i++)
		{
			printf("command: %x\n",command[i]);
		}
		for(i=0;i<strlen(tempbuf);i++)
		{
			printf("tempbuf: %x\n",tempbuf[i]);
		}
	*/
		if(isCommand(buffer,command))
		{
			if( args.verbose )
                		fprintf(stderr, "buffer equals command ,do not print command");
		}
		else
		{
			write( fileno(stdout), buffer, numread ); 
		}
	}

	return ret;
}




void sig_child(int signo)
{
	int status;
	pid_t pid = wait(&status);
	printf("child %d terminated.\r\n", pid);
	exit(0);
}


void *handlestdin(void *arg)
{
	int fd=*(int *)arg;

	while(1)
	{
		write_pass_fd( STDIN_FILENO, fd );
	}
}


int main(int argc, char *argv[])
{
	int opt_offset = parse_options(argc,argv);
	if( opt_offset<0 ) {
	// There was some error
	show_help();

        return -(opt_offset+1); // -1 becomes 0, -2 becomes 1 etc.
    }

    if( argc-opt_offset<1 ) {
	show_help();

        return 0;
    }

	//return runprogram( argc-opt_offset, argv+opt_offset );





	

	int pty;
	char pty_name[PATH_MAX];
	pid_t child;
	
	//signal(SIGCHLD, sig_child);

	child = forkpty(&pty,pty_name,NULL,NULL);
	if(child == -1)
	{
		perror("forkpty");
		exit(0);
	}
	else if(child ==0){
		int new_argc = argc-opt_offset;
		char **newargv = argv+opt_offset;
		char **new_argv=malloc(sizeof(char *)*(new_argc+1));
		int i;
		for( i=0; i<new_argc; ++i ) {
			new_argv[i]=newargv[i];
		}

		new_argv[i]=NULL;
		execvp( new_argv[0], new_argv );

		perror("su pass: Failed to run command");

		
	}

	// in parent process;
	//printf( "pty name: %s\n", pty_name ); 
	
	int temp;
	pthread_t ntid;
	
	int err;
	
	err = pthread_create(&ntid,NULL,handlestdin,&pty);
	if(err != 0){
		printf("can't create thread: %s\n",strerror(err));
		return 1;
	}


	int status=0;
    int terminate=0;
    pid_t wait_id;
	
	do{
		if( !terminate ) 
		{
			
			fd_set reads;
			FD_ZERO( &reads ); 
			FD_SET( pty, &reads ); 
			
			int selret = select( pty+1, &reads, NULL, NULL, NULL ); 
			
			if ( selret == -1 ){ 
				perror( "select" ); 
				break; 
			} 
			
			if(selret >0)
			{
				if(FD_ISSET(pty, &reads))
				{
					
					int ret =handleoutput(pty);
					if(ret>0)
					{
						//close(pty);
					}
					
				}
			}
			wait_id=waitpid( child, &status, WNOHANG );
		}
		else
		{
			wait_id=waitpid( child, &status, 0 );
		}
		
	}while(wait_id==0 || (!WIFEXITED( status ) && !WIFSIGNALED( status )));
	
	if( terminate>0 )
		return terminate;
	else if( WIFEXITED( status ) )
		return WEXITSTATUS(status);
	else
		return 255;

}
