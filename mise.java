org.springframework.ai.chat.client.advisor.RetrievalAugmentationAdvisor
//异步任务
public AdvisedRequest before(AdvisedRequest request) {
		Map<String, Object> context = new HashMap<>(request.adviseContext());

		// 0. Create a query from the user text, parameters, and conversation history.
		Query originalQuery = Query.builder()
			.text(new PromptTemplate(request.userText(), request.userParams()).render())
			.history(request.messages())
			.build();

		// 1. Transform original user query based on a chain of query transformers.
		Query transformedQuery = originalQuery;
		for (var queryTransformer : this.queryTransformers) {
			transformedQuery = queryTransformer.apply(transformedQuery);
		}

		// 2. Expand query into one or multiple queries.
		List<Query> expandedQueries = this.queryExpander != null ? this.queryExpander.expand(transformedQuery)
				: List.of(transformedQuery);

		// 3. Get similar documents for each query.
		Map<Query, List<List<Document>>> documentsForQuery = expandedQueries.stream()
			.map(query -> CompletableFuture.supplyAsync(() -> getDocumentsForQuery(query), this.taskExecutor))
			.toList()
			.stream()
			.map(CompletableFuture::join)
			.collect(Collectors.toMap(Map.Entry::getKey, entry -> List.of(entry.getValue())));

		// 4. Combine documents retrieved based on multiple queries and from multiple data
		// sources.
		List<Document> documents = this.documentJoiner.join(documentsForQuery);
		context.put(DOCUMENT_CONTEXT, documents);

		// 5. Augment user query with the document contextual data.
		Query augmentedQuery = this.queryAugmenter.augment(originalQuery, documents);

		// 6. Update advised request with augmented prompt.
		return AdvisedRequest.from(request).userText(augmentedQuery.text()).adviseContext(context).build();
	}  


public class QueryParameters {

    @QueryValue("values")
    private final Map<String, String> parameters;

    public QueryParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    @Override
    public String toString() {
        return parameters.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining(", ", "{", "}"));
    }
}

//动态条件构建
public class FilterExpressionBuilder {

	public Op eq(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.EQ, new Key(key), new Value(value)));
	}

	public Op ne(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.NE, new Key(key), new Value(value)));
	}

	public Op gt(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.GT, new Key(key), new Value(value)));
	}

	public Op gte(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.GTE, new Key(key), new Value(value)));
	}

	public Op lt(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.LT, new Key(key), new Value(value)));
	}

	public Op lte(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.LTE, new Key(key), new Value(value)));
	}

	public Op and(Op left, Op right) {
		return new Op(new Filter.Expression(ExpressionType.AND, left.expression, right.expression));
	}

	public Op or(Op left, Op right) {
		return new Op(new Filter.Expression(ExpressionType.OR, left.expression, right.expression));
	}

	public Op in(String key, Object... values) {
		return this.in(key, List.of(values));
	}

	public Op in(String key, List<Object> values) {
		return new Op(new Filter.Expression(ExpressionType.IN, new Key(key), new Value(values)));
	}

	public Op nin(String key, Object... values) {
		return this.nin(key, List.of(values));
	}

	public Op nin(String key, List<Object> values) {
		return new Op(new Filter.Expression(ExpressionType.NIN, new Key(key), new Value(values)));
	}

	public Op group(Op content) {
		return new Op(new Filter.Group(content.build()));
	}

	public Op not(Op content) {
		return new Op(new Filter.Expression(ExpressionType.NOT, content.expression, null));
	}

	public record Op(Filter.Operand expression) {

		public Filter.Expression build() {
			if (this.expression instanceof Filter.Group group) {
				// Remove the top-level grouping.
				return group.content();
			}
			else if (this.expression instanceof Filter.Expression exp) {
				return exp;
			}
			throw new RuntimeException("Invalid expression: " + this.expression);
		}

	}

}


//链式流程定义
private ApiCall<ApiResponse<AlbumObject>, ApiException> prepareGetAnAlbumRequest(
            final String id,
            final String market) throws IOException {
        return new ApiCall.Builder<ApiResponse<AlbumObject>, ApiException>()
                .globalConfig(getGlobalConfiguration())
                .requestBuilder(requestBuilder -> requestBuilder
                        .server(Server.ENUM_DEFAULT.value())
                        .path("/albums/{id}")
                        .queryParam(param -> param.key("market")
                                .value(market).isRequired(false))
                        .templateParam(param -> param.key("id").value(id)
                                .shouldEncode(true))
                        .headerParam(param -> param.key("accept").value("application/json"))
                        .withAuth(auth -> auth
                                .add("oauth_2_0"))
                        .arraySerializationFormat(ArraySerializationFormat.CSV)
                        .httpMethod(HttpMethod.GET)
                )
                .responseHandler(responseHandler -> responseHandler
                        .responseClassType(ResponseClassType.API_RESPONSE)
                        .apiResponseDeserializer(
                                response -> ApiHelper.deserialize(response, AlbumObject.class))
                        .nullify404(false)
                        .localErrorCase("401",
                                ErrorCase.setReason("Bad or expired token. This can happen if the user revoked a token or\nthe access token has expired. You should re-authenticate the user.\n",
                                        (reason, context) -> new UnauthorizedException(reason, context)))
                        .localErrorCase("403",
                                ErrorCase.setReason("Bad OAuth request (wrong consumer key, bad nonce, expired\ntimestamp...). Unfortunately, re-authenticating the user won't help here.\n",
                                        (reason, context) -> new ForbiddenException(reason, context)))
                        .localErrorCase("429",
                                ErrorCase.setReason("The app has exceeded its rate limits.\n",
                                        (reason, context) -> new TooManyRequestsException(reason, context)))
                        .globalErrorCase(GLOBAL_ERROR_CASES))
                .build();
    }

 //user请求自动符值
  @Bean
  @Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
  public User.UserBuilder callerBuilder() {
    return User.builder();
  }

//factory返回值不固定
public interface HttpClientFactory<T> {

    T create(HttpClientSettings settings);

}
//aws-sdk-java
public class ApacheHttpClientFactory implements HttpClientFactory<ConnectionManagerAwareHttpClient> {
}

//eventstore expression
   void testSelectWhere() {
        SelectBuilder builder = new SelectBuilder(database, of(COL_T1_01, COL_T1_02, COL_T1_03));
        builder.from(TABLE_T1);
        builder.where(eq(COL_T1_02));
        assertEquals("SELECT col_T1_01,col_T1_02,col_T1_03 FROM T1 WHERE col_T1_02=?", builder.<SqlQuery>build().sql());

        builder = new SelectBuilder(database, of(COL_T1_01, COL_T1_02, COL_T1_03));
        builder.from(TABLE_T1);
        builder.where(and(eq(COL_T1_02), eq(COL_T1_03)));
        assertEquals("SELECT col_T1_01,col_T1_02,col_T1_03 FROM T1 WHERE (col_T1_02=? AND col_T1_03=?)", builder.<SqlQuery>build().sql());
    }

//enenvstrorm antlr4
    public static PageRequest parse(String query, EvaluatorDefinition evaluatorDefinition) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("parseQuery [{}]", query);
        }

        if (Strings.isEmpty(query)) {
            throw new PageRequestException(PageRequestException.Type.EMPTY, ImmutableMap.of());
        }

        RequestContext ctx = parse(query);

        PageRequestBuilder builder = parseRange(query, ctx.range());
        parseFilter(builder, ctx.filter(), evaluatorDefinition);
        parseSort(builder, ctx.sort());

        builder.withEvaluator(evaluatorDefinition);

        return builder.build();
    }


//retry
public class RetryUtility {
    
    private final int maxRetries;
    private final Duration initialDelay;
    private final double backoffMultiplier;
    private final Duration maxDelay;
    private final Predicate<Exception> retryCondition;
    
    public RetryUtility(int maxRetries, Duration initialDelay, double backoffMultiplier, 
                       Duration maxDelay, Predicate<Exception> retryCondition) {
        this.maxRetries = maxRetries;
        this.initialDelay = initialDelay;
        this.backoffMultiplier = backoffMultiplier;
        this.maxDelay = maxDelay;
        this.retryCondition = retryCondition;
    }
    
    public static RetryUtility defaultNetworkRetry() {
        return new RetryUtility(
            3,
            Duration.ofMillis(1000),
            2.0,
            Duration.ofSeconds(30),
            e -> e instanceof IOException || e instanceof RuntimeException
        );
    }
    
    public <T> T execute(Callable<T> operation) throws Exception {
        Exception lastException = null;
        Duration currentDelay = initialDelay;
        
        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                System.out.println("Attempt " + (attempt + 1) + "/" + (maxRetries + 1));
                return operation.call();
            } catch (Exception e) {
                lastException = e;
                
                if (attempt == maxRetries || !retryCondition.test(e)) {
                    System.err.println("Max retries reached or non-retryable exception. Giving up.");
                    throw e;
                }
                
                System.err.println("Attempt " + (attempt + 1) + " failed: " + e.getMessage());
                System.out.println("Retrying in " + currentDelay.toMillis() + "ms...");
                
                try {
                    Thread.sleep(currentDelay.toMillis());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Retry interrupted", ie);
                }
                
                // Calculate next delay with exponential backoff
                currentDelay = Duration.ofMillis(
                    Math.min((long)(currentDelay.toMillis() * backoffMultiplier), maxDelay.toMillis())
                );
            }
        }
        
        throw lastException;
    }
    
    // Simulate network service
    static class NetworkService {
        private static final Random random = new Random();
        private int callCount = 0;
        
        public String makeNetworkCall() throws IOException {
            callCount++;
            
            // Simulate network failures
            if (callCount <= 2 && random.nextBoolean()) {
                throw new IOException("Network timeout - attempt " + callCount);
            }
            
            return "Success after " + callCount + " attempts";
        }
    }
    
    public static void main(String[] args) {
        RetryUtility retry = RetryUtility.defaultNetworkRetry();
        NetworkService service = new NetworkService();
        
        try {
            String result = retry.execute(service::makeNetworkCall);
            System.out.println("Result: " + result);
        } catch (Exception e) {
            System.err.println("Final failure: " + e.getMessage());
        }
    }
}

//spring configuration类先执行autowrited再执行初始化bean


@Configuration(proxyBeanMethods = false)
public class WebSecurityConfiguration implements ImportAware, BeanClassLoaderAware {

	private WebSecurity webSecurity;

	private Boolean debugEnabled;

	private List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers;

	private List<SecurityFilterChain> securityFilterChains = Collections.emptyList();

	private List<WebSecurityCustomizer> webSecurityCustomizers = Collections.emptyList();

	private ClassLoader beanClassLoader;

	@Autowired(required = false)
	private ObjectPostProcessor<Object> objectObjectPostProcessor;

	@Autowired(required = false)
	private HttpSecurity httpSecurity;

	@Bean
	public static DelegatingApplicationListener delegatingApplicationListener() {
		return new DelegatingApplicationListener();
	}

	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
		return this.webSecurity.getExpressionHandler();
	}

	/**
	 * Creates the Spring Security Filter Chain
	 * @return the {@link Filter} that represents the security filter chain
	 * @throws Exception
	 */
	@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public Filter springSecurityFilterChain() throws Exception {
		boolean hasFilterChain = !this.securityFilterChains.isEmpty();
		if (!hasFilterChain) {
			this.webSecurity.addSecurityFilterChainBuilder(() -> {
				this.httpSecurity.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());
				this.httpSecurity.formLogin(Customizer.withDefaults());
				this.httpSecurity.httpBasic(Customizer.withDefaults());
				return this.httpSecurity.build();
			});
		}
		for (SecurityFilterChain securityFilterChain : this.securityFilterChains) {
			this.webSecurity.addSecurityFilterChainBuilder(() -> securityFilterChain);
		}
		for (WebSecurityCustomizer customizer : this.webSecurityCustomizers) {
			customizer.customize(this.webSecurity);
		}
		return this.webSecurity.build();
	}

	/**
	 * Creates the {@link WebInvocationPrivilegeEvaluator} that is necessary to evaluate
	 * privileges for a given web URI
	 * @return the {@link WebInvocationPrivilegeEvaluator}
	 */
	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public WebInvocationPrivilegeEvaluator privilegeEvaluator() {
		return this.webSecurity.getPrivilegeEvaluator();
	}

	/**
	 * Sets the {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>}
	 * instances used to create the web configuration.
	 * @param objectPostProcessor the {@link ObjectPostProcessor} used to create a
	 * {@link WebSecurity} instance
	 * @param beanFactory the bean factory to use to retrieve the relevant
	 * {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>} instances used to
	 * create the web configuration
	 * @throws Exception
	 */
	@Autowired(required = false)
	public void setFilterChainProxySecurityConfigurer(ObjectPostProcessor<Object> objectPostProcessor,
			ConfigurableListableBeanFactory beanFactory) throws Exception {
		this.webSecurity = objectPostProcessor.postProcess(new WebSecurity(objectPostProcessor));
		if (this.debugEnabled != null) {
			this.webSecurity.debug(this.debugEnabled);
		}
		List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers = new AutowiredWebSecurityConfigurersIgnoreParents(
				beanFactory)
			.getWebSecurityConfigurers();
		webSecurityConfigurers.sort(AnnotationAwareOrderComparator.INSTANCE);
		Integer previousOrder = null;
		Object previousConfig = null;
		for (SecurityConfigurer<Filter, WebSecurity> config : webSecurityConfigurers) {
			Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
			if (previousOrder != null && previousOrder.equals(order)) {
				throw new IllegalStateException("@Order on WebSecurityConfigurers must be unique. Order of " + order
						+ " was already used on " + previousConfig + ", so it cannot be used on " + config + " too.");
			}
			previousOrder = order;
			previousConfig = config;
		}
		for (SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
			this.webSecurity.apply(webSecurityConfigurer);
		}
		this.webSecurityConfigurers = webSecurityConfigurers;
	}

	@Autowired(required = false)
	void setFilterChains(List<SecurityFilterChain> securityFilterChains) {
		this.securityFilterChains = securityFilterChains;
	}

	@Autowired(required = false)
	void setWebSecurityCustomizers(List<WebSecurityCustomizer> webSecurityCustomizers) {
		this.webSecurityCustomizers = webSecurityCustomizers;
	}

	@Bean
	public static BeanFactoryPostProcessor conversionServicePostProcessor() {
		return new RsaKeyConversionServicePostProcessor();
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		Map<String, Object> enableWebSecurityAttrMap = importMetadata
			.getAnnotationAttributes(EnableWebSecurity.class.getName());
		AnnotationAttributes enableWebSecurityAttrs = AnnotationAttributes.fromMap(enableWebSecurityAttrMap);
		this.debugEnabled = enableWebSecurityAttrs.getBoolean("debug");
		if (this.webSecurity != null) {
			this.webSecurity.debug(this.debugEnabled);
		}
	}

	@Override
	public void setBeanClassLoader(ClassLoader classLoader) {
		this.beanClassLoader = classLoader;
	}

	/**
	 * A custom version of the Spring provided AnnotationAwareOrderComparator that uses
	 * {@link AnnotationUtils#findAnnotation(Class, Class)} to look on super class
	 * instances for the {@link Order} annotation.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private static class AnnotationAwareOrderComparator extends OrderComparator {

		private static final AnnotationAwareOrderComparator INSTANCE = new AnnotationAwareOrderComparator();

		@Override
		protected int getOrder(Object obj) {
			return lookupOrder(obj);
		}

		private static int lookupOrder(Object obj) {
			if (obj instanceof Ordered) {
				return ((Ordered) obj).getOrder();
			}
			if (obj != null) {
				Class<?> clazz = ((obj instanceof Class) ? (Class<?>) obj : obj.getClass());
				Order order = AnnotationUtils.findAnnotation(clazz, Order.class);
				if (order != null) {
					return order.value();
				}
			}
			return Ordered.LOWEST_PRECEDENCE;
		}

	}

}

public final class JdbcOneTimeTokenService implements OneTimeTokenService, DisposableBean, InitializingBean {

	private final Log logger = LogFactory.getLog(getClass());

	private final JdbcOperations jdbcOperations;

	private Function<OneTimeToken, List<SqlParameterValue>> oneTimeTokenParametersMapper = new OneTimeTokenParametersMapper();

	private RowMapper<OneTimeToken> oneTimeTokenRowMapper = new OneTimeTokenRowMapper();

	private Clock clock = Clock.systemUTC();

	private ThreadPoolTaskScheduler taskScheduler;

	private static final String DEFAULT_CLEANUP_CRON = "@hourly";

	private static final String TABLE_NAME = "one_time_tokens";

	// @formatter:off
	private static final String COLUMN_NAMES = "token_value, "
			+ "username, "
			+ "expires_at";
	// @formatter:on

	// @formatter:off
	private static final String SAVE_ONE_TIME_TOKEN_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?)";
	// @formatter:on

	private static final String FILTER = "token_value = ?";

	private static final String DELETE_ONE_TIME_TOKEN_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + FILTER;

	// @formatter:off
	private static final String SELECT_ONE_TIME_TOKEN_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + FILTER;
	// @formatter:on

	// @formatter:off
	private static final String DELETE_ONE_TIME_TOKENS_BY_EXPIRY_TIME_QUERY = "DELETE FROM "
			+ TABLE_NAME
			+ " WHERE expires_at < ?";
	// @formatter:on

	/**
	 * Constructs a {@code JdbcOneTimeTokenService} using the provide parameters.
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcOneTimeTokenService(JdbcOperations jdbcOperations) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.taskScheduler = createTaskScheduler(DEFAULT_CLEANUP_CRON);
	}

	/**
	 * Sets the chron expression used for cleaning up expired tokens. The default is to
	 * run hourly.
	 *
	 * For more advanced use cases the cleanupCron may be set to null which will disable
	 * the built-in cleanup. Users can then invoke {@link #cleanupExpiredTokens()} using
	 * custom logic.
	 * @param cleanupCron the chron expression passed to {@link CronTrigger} used for
	 * determining how frequent to perform cleanup. The default is "@hourly".
	 * @see CronTrigger
	 * @see #cleanupExpiredTokens()
	 */
	public void setCleanupCron(String cleanupCron) {
		this.taskScheduler = createTaskScheduler(cleanupCron);
	}

	@Override
	public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
		Assert.notNull(request, "generateOneTimeTokenRequest cannot be null");
		String token = UUID.randomUUID().toString();
		Instant expiresAt = this.clock.instant().plus(request.getExpiresIn());
		OneTimeToken oneTimeToken = new DefaultOneTimeToken(token, request.getUsername(), expiresAt);
		insertOneTimeToken(oneTimeToken);
		return oneTimeToken;
	}

	private void insertOneTimeToken(OneTimeToken oneTimeToken) {
		List<SqlParameterValue> parameters = this.oneTimeTokenParametersMapper.apply(oneTimeToken);
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(SAVE_ONE_TIME_TOKEN_SQL, pss);
	}

	@Override
	public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
		Assert.notNull(authenticationToken, "authenticationToken cannot be null");

		List<OneTimeToken> tokens = selectOneTimeToken(authenticationToken);
		if (CollectionUtils.isEmpty(tokens)) {
			return null;
		}
		OneTimeToken token = tokens.get(0);
		deleteOneTimeToken(token);
		if (isExpired(token)) {
			return null;
		}
		return token;
	}

	private boolean isExpired(OneTimeToken ott) {
		return this.clock.instant().isAfter(ott.getExpiresAt());
	}

	private List<OneTimeToken> selectOneTimeToken(OneTimeTokenAuthenticationToken authenticationToken) {
		List<SqlParameterValue> parameters = List
			.of(new SqlParameterValue(Types.VARCHAR, authenticationToken.getTokenValue()));
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		return this.jdbcOperations.query(SELECT_ONE_TIME_TOKEN_SQL, pss, this.oneTimeTokenRowMapper);
	}

	private void deleteOneTimeToken(OneTimeToken oneTimeToken) {
		List<SqlParameterValue> parameters = List
			.of(new SqlParameterValue(Types.VARCHAR, oneTimeToken.getTokenValue()));
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(DELETE_ONE_TIME_TOKEN_SQL, pss);
	}

	private ThreadPoolTaskScheduler createTaskScheduler(String cleanupCron) {
		if (cleanupCron == null) {
			return null;
		}
		ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
		taskScheduler.setThreadNamePrefix("spring-one-time-tokens-");
		taskScheduler.initialize();
		taskScheduler.schedule(this::cleanupExpiredTokens, new CronTrigger(cleanupCron));
		return taskScheduler;
	}

	public void cleanupExpiredTokens() {
		List<SqlParameterValue> parameters = List
			.of(new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(Instant.now())));
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		int deletedCount = this.jdbcOperations.update(DELETE_ONE_TIME_TOKENS_BY_EXPIRY_TIME_QUERY, pss);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug("Cleaned up " + deletedCount + " expired tokens");
		}
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		this.taskScheduler.afterPropertiesSet();
	}

	@Override
	public void destroy() throws Exception {
		if (this.taskScheduler != null) {
			this.taskScheduler.shutdown();
		}
	}

	/**
	 * Sets the {@link Clock} used when generating one-time token and checking token
	 * expiry.
	 * @param clock the clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	/**
	 * The default {@code Function} that maps {@link OneTimeToken} to a {@code List} of
	 * {@link SqlParameterValue}.
	 *
	 * @author Max Batischev
	 * @since 6.4
	 */
	private static class OneTimeTokenParametersMapper implements Function<OneTimeToken, List<SqlParameterValue>> {

		@Override
		public List<SqlParameterValue> apply(OneTimeToken oneTimeToken) {
			List<SqlParameterValue> parameters = new ArrayList<>();
			parameters.add(new SqlParameterValue(Types.VARCHAR, oneTimeToken.getTokenValue()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, oneTimeToken.getUsername()));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(oneTimeToken.getExpiresAt())));
			return parameters;
		}

	}

	/**
	 * The default {@link RowMapper} that maps the current row in
	 * {@code java.sql.ResultSet} to {@link OneTimeToken}.
	 *
	 * @author Max Batischev
	 * @since 6.4
	 */
	private static class OneTimeTokenRowMapper implements RowMapper<OneTimeToken> {

		@Override
		public OneTimeToken mapRow(ResultSet rs, int rowNum) throws SQLException {
			String tokenValue = rs.getString("token_value");
			String userName = rs.getString("username");
			Instant expiresAt = rs.getTimestamp("expires_at").toInstant();
			return new DefaultOneTimeToken(tokenValue, userName, expiresAt);
		}

	}

}
//任务编排

    public TaskBuilder initTasks(final InitStrategy initStrategy) {
        TaskBuilder builder;
        if (!pluginListed) {
            builder = new TaskGraphBuilder() {
                List<File> archives;
                Collection<String> bundledPlugins;

                {
                    Handle loadBundledPlugins = add("Loading bundled plugins", new Executable() {
                        @Override
                        public void run(Reactor session) throws Exception {
                            bundledPlugins = loadBundledPlugins();
                        }
                    });

                    Handle listUpPlugins = requires(loadBundledPlugins).add("Listing up plugins", new Executable() {
                        @Override
                        public void run(Reactor session) throws Exception {
                            archives = initStrategy.listPluginArchives(PluginManager.this);
                        }
                    });

                    requires(listUpPlugins).attains(PLUGINS_LISTED).add("Preparing plugins", new Executable() {
                        @Override
                        public void run(Reactor session) throws Exception {
                            // once we've listed plugins, we can fill in the reactor with plugin-specific initialization tasks
                            TaskGraphBuilder g = new TaskGraphBuilder();

                            final Map<String, File> inspectedShortNames = new HashMap<>();

                            for (final File arc : archives) {
                                g.followedBy().notFatal().attains(PLUGINS_LISTED).add("Inspecting plugin " + arc, new Executable() {
                                    @Override
                                    public void run(Reactor session1) throws Exception {
                                        try {
                                            PluginWrapper p = strategy.createPluginWrapper(arc);
                                            if (isDuplicate(p)) return;

                                            p.isBundled = containsHpiJpi(bundledPlugins, arc.getName());
                                            plugins.add(p);
                                        } catch (IOException e) {
                                            failedPlugins.add(new FailedPlugin(arc.getName(), e));
                                            throw e;
                                        }
                                    }

                                    /**
                                     * Inspects duplication. this happens when you run hpi:run on a bundled plugin,
                                     * as well as putting numbered jpi files, like "cobertura-1.0.jpi" and "cobertura-1.1.jpi"
                                     */
                                    private boolean isDuplicate(PluginWrapper p) {
                                        String shortName = p.getShortName();
                                        if (inspectedShortNames.containsKey(shortName)) {
                                            LOGGER.info("Ignoring " + arc + " because " + inspectedShortNames.get(shortName) + " is already loaded");
                                            return true;
                                        }

                                        inspectedShortNames.put(shortName, arc);
                                        return false;
                                    }
                                });
                            }

                            g.followedBy().attains(PLUGINS_LISTED).add("Checking cyclic dependencies", new Executable() {
                                /**
                                 * Makes sure there's no cycle in dependencies.
                                 */
                                @Override
                                public void run(Reactor reactor) throws Exception {
                                    try {
                                        CyclicGraphDetector<PluginWrapper> cgd = new CyclicGraphDetector<>() {
                                            @Override
                                            protected List<PluginWrapper> getEdges(PluginWrapper p) {
                                                List<PluginWrapper> next = new ArrayList<>();
                                                addTo(p.getDependencies(), next);
                                                addTo(p.getOptionalDependencies(), next);
                                                return next;
                                            }

                                            private void addTo(List<Dependency> dependencies, List<PluginWrapper> r) {
                                                for (Dependency d : dependencies) {
                                                    PluginWrapper p = getPlugin(d.shortName);
                                                    if (p != null)
                                                        r.add(p);
                                                }
                                            }

                                            @Override
                                            protected void reactOnCycle(PluginWrapper q, List<PluginWrapper> cycle) {

                                                LOGGER.log(Level.SEVERE, "found cycle in plugin dependencies: (root=" + q + ", deactivating all involved) " + cycle.stream().map(Object::toString).collect(Collectors.joining(" -> ")));
                                                for (PluginWrapper pluginWrapper : cycle) {
                                                    pluginWrapper.setHasCycleDependency(true);
                                                    failedPlugins.add(new FailedPlugin(pluginWrapper, new CycleDetectedException(cycle)));
                                                }
                                            }

                                        };
                                        cgd.run(getPlugins());

                                        // obtain topologically sorted list and overwrite the list
                                        for (PluginWrapper p : cgd.getSorted()) {
                                            if (p.isActive()) {
                                                activePlugins.add(p);
                                                ((UberClassLoader) uberClassLoader).clearCacheMisses();
                                            }
                                        }
                                    } catch (CycleDetectedException e) { // TODO this should be impossible, since we override reactOnCycle to not throw the exception
                                        stop(); // disable all plugins since classloading from them can lead to StackOverflow
                                        throw e;    // let Hudson fail
                                    }
                                }
                            });

                            session.addAll(g.discoverTasks(session));

                            pluginListed = true; // technically speaking this is still too early, as at this point tasks are merely scheduled, not necessarily executed.
                        }
                    });
                }
            };
        } else {
            builder = TaskBuilder.EMPTY_BUILDER;
        }

        final InitializerFinder initializerFinder = new InitializerFinder(uberClassLoader);        // misc. stuff

        // lists up initialization tasks about loading plugins.
        return TaskBuilder.union(initializerFinder, // this scans @Initializer in the core once
                builder, new TaskGraphBuilder() {{
            requires(PLUGINS_LISTED).attains(PLUGINS_PREPARED).add("Loading plugins", new Executable() {
                /**
                 * Once the plugins are listed, schedule their initialization.
                 */
                @Override
                public void run(Reactor session) throws Exception {
                    Jenkins.get().lookup.set(PluginInstanceStore.class, new PluginInstanceStore());
                    TaskGraphBuilder g = new TaskGraphBuilder();

                    // schedule execution of loading plugins
                    for (final PluginWrapper p : activePlugins.toArray(new PluginWrapper[0])) {
                        g.followedBy().notFatal().attains(PLUGINS_PREPARED).add(String.format("Loading plugin %s v%s (%s)", p.getLongName(), p.getVersion(), p.getShortName()), new Executable() {
                            @Override
                            public void run(Reactor session) throws Exception {
                                try {
                                    p.resolvePluginDependencies();
                                    strategy.load(p);
                                } catch (MissingDependencyException e) {
                                    failedPlugins.add(new FailedPlugin(p, e));
                                    activePlugins.remove(p);
                                    plugins.remove(p);
                                    p.releaseClassLoader();
                                    LOGGER.log(Level.SEVERE, "Failed to install {0}: {1}", new Object[] { p.getShortName(), e.getMessage() });
                                } catch (IOException e) {
                                    failedPlugins.add(new FailedPlugin(p, e));
                                    activePlugins.remove(p);
                                    plugins.remove(p);
                                    p.releaseClassLoader();
                                    throw e;
                                }
                            }
                        });
                    }

                    // schedule execution of initializing plugins
                    for (final PluginWrapper p : activePlugins.toArray(new PluginWrapper[0])) {
                        g.followedBy().notFatal().attains(PLUGINS_STARTED).add("Initializing plugin " + p.getShortName(), new Executable() {
                            @Override
                            public void run(Reactor session) throws Exception {
                                if (!activePlugins.contains(p)) {
                                    return;
                                }
                                try {
                                    p.getPluginOrFail().postInitialize();
                                } catch (Exception e) {
                                    failedPlugins.add(new FailedPlugin(p, e));
                                    activePlugins.remove(p);
                                    plugins.remove(p);
                                    p.releaseClassLoader();
                                    throw e;
                                }
                            }
                        });
                    }

                    g.followedBy().attains(PLUGINS_STARTED).add("Discovering plugin initialization tasks", new Executable() {
                        @Override
                        public void run(Reactor reactor) throws Exception {
                            // rescan to find plugin-contributed @Initializer
                            reactor.addAll(initializerFinder.discoverTasks(reactor));
                        }
                    });

                    // register them all
                    session.addAll(g.discoverTasks(session));
                }
            });

            // All plugins are loaded. Now we can figure out who depends on who.
            requires(PLUGINS_PREPARED).attains(COMPLETED).add("Resolving Dependent Plugins Graph", new Executable() {
                @Override
                public void run(Reactor reactor) throws Exception {
                    resolveDependentPlugins();
                }
            });
        }});
    }
public final class DefaultBearerTokenResolver implements BearerTokenResolver {


	@Override
	public String resolve(final HttpServletRequest request) {
		// @formatter:off
		return resolveToken(
			resolveFromAuthorizationHeader(request),
			resolveAccessTokenFromQueryString(request),
			resolveAccessTokenFromBody(request)
		);
		// @formatter:on
	}

}

public final class ConfigurationSettingNames {

	private static final String SETTINGS_NAMESPACE = "settings.";

	private ConfigurationSettingNames() {
	}

	/**
	 * The names for client configuration settings.
	 */
	public static final class Client {

		private static final String CLIENT_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE.concat("client.");

		/**
		 * Set to {@code true} if the client is required to provide a proof key challenge
		 * and verifier when performing the Authorization Code Grant flow.
		 */
		public static final String REQUIRE_PROOF_KEY = CLIENT_SETTINGS_NAMESPACE.concat("require-proof-key");

		/**
		 * Set to {@code true} if authorization consent is required when the client
		 * requests access. This applies to all interactive flows (e.g.
		 * {@code authorization_code} and {@code device_code}).
		 */
		public static final String REQUIRE_AUTHORIZATION_CONSENT = CLIENT_SETTINGS_NAMESPACE
			.concat("require-authorization-consent");

		/**
		 * Set the {@code URL} for the Client's JSON Web Key Set.
		 * @since 0.2.2
		 */
		public static final String JWK_SET_URL = CLIENT_SETTINGS_NAMESPACE.concat("jwk-set-url");

		/**
		 * Set the {@link JwsAlgorithm JWS} algorithm that must be used for signing the
		 * {@link Jwt JWT} used to authenticate the Client at the Token Endpoint for the
		 * {@link ClientAuthenticationMethod#PRIVATE_KEY_JWT private_key_jwt} and
		 * {@link ClientAuthenticationMethod#CLIENT_SECRET_JWT client_secret_jwt}
		 * authentication methods.
		 * @since 0.2.2
		 */
		public static final String TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM = CLIENT_SETTINGS_NAMESPACE
			.concat("token-endpoint-authentication-signing-algorithm");

		/**
		 * Set the expected subject distinguished name associated to the client
		 * {@code X509Certificate} received during client authentication when using the
		 * {@code tls_client_auth} method.
		 * @since 1.3
		 */
		public static final String X509_CERTIFICATE_SUBJECT_DN = CLIENT_SETTINGS_NAMESPACE
			.concat("x509-certificate-subject-dn");

		private Client() {
		}

	}

	/**
	 * The names for authorization server configuration settings.
	 */
	public static final class AuthorizationServer {

		private static final String AUTHORIZATION_SERVER_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE
			.concat("authorization-server.");

		/**
		 * Set the URL the Authorization Server uses as its Issuer Identifier.
		 */
		public static final String ISSUER = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE.concat("issuer");

		/**
		 * Set to {@code true} if multiple issuers are allowed per host.
		 * @since 1.3
		 */
		public static final String MULTIPLE_ISSUERS_ALLOWED = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("multiple-issuers-allowed");

		/**
		 * Set the OAuth 2.0 Authorization endpoint.
		 */
		public static final String AUTHORIZATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("authorization-endpoint");

		/**
		 * Set the OAuth 2.0 Device Authorization endpoint.
		 */
		public static final String DEVICE_AUTHORIZATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("device-authorization-endpoint");

		/**
		 * Set the OAuth 2.0 Device Verification endpoint.
		 */
		public static final String DEVICE_VERIFICATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("device-verification-endpoint");

		/**
		 * Set the OAuth 2.0 Token endpoint.
		 */
		public static final String TOKEN_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE.concat("token-endpoint");

		/**
		 * Set the JWK Set endpoint.
		 */
		public static final String JWK_SET_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("jwk-set-endpoint");

		/**
		 * Set the OAuth 2.0 Token Revocation endpoint.
		 */
		public static final String TOKEN_REVOCATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("token-revocation-endpoint");

		/**
		 * Set the OAuth 2.0 Token Introspection endpoint.
		 */
		public static final String TOKEN_INTROSPECTION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("token-introspection-endpoint");

		/**
		 * Set the OpenID Connect 1.0 Client Registration endpoint.
		 */
		public static final String OIDC_CLIENT_REGISTRATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("oidc-client-registration-endpoint");

		/**
		 * Set the OpenID Connect 1.0 UserInfo endpoint.
		 */
		public static final String OIDC_USER_INFO_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("oidc-user-info-endpoint");

		/**
		 * Set the OpenID Connect 1.0 Logout endpoint.
		 * @since 1.1
		 */
		public static final String OIDC_LOGOUT_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE
			.concat("oidc-logout-endpoint");

		private AuthorizationServer() {
		}

	}

	/**
	 * The names for token configuration settings.
	 */
	public static final class Token {

		private static final String TOKEN_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE.concat("token.");

		/**
		 * Set the time-to-live for an authorization code.
		 * @since 0.4.0
		 */
		public static final String AUTHORIZATION_CODE_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE
			.concat("authorization-code-time-to-live");

		/**
		 * Set the time-to-live for an access token.
		 */
		public static final String ACCESS_TOKEN_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE
			.concat("access-token-time-to-live");

		/**
		 * Set the {@link OAuth2TokenFormat token format} for an access token.
		 * @since 0.2.3
		 */
		public static final String ACCESS_TOKEN_FORMAT = TOKEN_SETTINGS_NAMESPACE.concat("access-token-format");

		/**
		 * Set the time-to-live for a device code.
		 * @since 1.1
		 */
		public static final String DEVICE_CODE_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE
			.concat("device-code-time-to-live");

		/**
		 * Set to {@code true} if refresh tokens are reused when returning the access
		 * token response, or {@code false} if a new refresh token is issued.
		 */
		public static final String REUSE_REFRESH_TOKENS = TOKEN_SETTINGS_NAMESPACE.concat("reuse-refresh-tokens");

		/**
		 * Set the time-to-live for a refresh token.
		 */
		public static final String REFRESH_TOKEN_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE
			.concat("refresh-token-time-to-live");

		/**
		 * Set the {@link SignatureAlgorithm JWS} algorithm for signing the
		 * {@link OidcIdToken ID Token}.
		 */
		public static final String ID_TOKEN_SIGNATURE_ALGORITHM = TOKEN_SETTINGS_NAMESPACE
			.concat("id-token-signature-algorithm");

		/**
		 * Set to {@code true} if access tokens must be bound to the client
		 * {@code X509Certificate} received during client authentication when using the
		 * {@code tls_client_auth} or {@code self_signed_tls_client_auth} method.
		 * @since 1.3
		 */
		public static final String X509_CERTIFICATE_BOUND_ACCESS_TOKENS = TOKEN_SETTINGS_NAMESPACE
			.concat("x509-certificate-bound-access-tokens");

		private Token() {
		}

	}

}


/*
 * =============================================================================
 *
 *   Copyright (c) 2011-2018, The THYMELEAF team (http://www.thymeleaf.org)
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 * =============================================================================
 */
package org.thymeleaf.spring6.view;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.Ordered;
import org.springframework.util.PatternMatchUtils;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.AbstractCachingViewResolver;
import org.springframework.web.servlet.view.InternalResourceView;
import org.springframework.web.servlet.view.RedirectView;
import org.thymeleaf.spring6.ISpringTemplateEngine;


强制手动注入viewclass
public class ThymeleafViewResolver
        extends AbstractCachingViewResolver
        implements Ordered {


    private static final Logger vrlogger = LoggerFactory.getLogger(ThymeleafViewResolver.class);


    /**
     * <p>
     *   Prefix to be used in view names (returned by controllers) for specifying an
     *   HTTP redirect.
     * </p>
     * <p>
     *   Value: {@code redirect:}
     * </p>
     */
    public static final String REDIRECT_URL_PREFIX = "redirect:";

    /**
     * <p>
     *   Prefix to be used in view names (returned by controllers) for specifying an
     *   HTTP forward.
     * </p>
     * <p>
     *   Value: {@code forward:}
     * </p>
     */
    public static final String FORWARD_URL_PREFIX = "forward:";

    private boolean redirectContextRelative = true;
    private boolean redirectHttp10Compatible = true;

    private boolean alwaysProcessRedirectAndForward = true;

    private boolean producePartialOutputWhileProcessing = AbstractThymeleafView.DEFAULT_PRODUCE_PARTIAL_OUTPUT_WHILE_PROCESSING;

    private Class<? extends AbstractThymeleafView> viewClass = ThymeleafView.class;
    private String[] viewNames = null;
    private String[] excludedViewNames = null;
    private int order = Integer.MAX_VALUE;


    private final Map<String, Object> staticVariables = new LinkedHashMap<String, Object>(10);
    private String contentType = null;
    private boolean forceContentType = false;
    private String characterEncoding = null;

    private ISpringTemplateEngine templateEngine;



    /**
     * <p>
     *   Create an instance of ThymeleafViewResolver.
     * </p>
     */
    public ThymeleafViewResolver() {
        super();
    }




    /**
     * <p>
     *   Set the view class that should be used to create views. This must be a subclass
     *   of {@link AbstractThymeleafView}. The default value is {@link ThymeleafView}.
     * </p>
     *
     * @param viewClass class that is assignable to the required view class
     *        (by default, {@link ThymeleafView}).
     */
    public void setViewClass(final Class<? extends AbstractThymeleafView> viewClass) {
        if (viewClass == null || !AbstractThymeleafView.class.isAssignableFrom(viewClass)) {
            throw new IllegalArgumentException(
                    "Given view class [" + (viewClass != null ? viewClass.getName() : null) +
                    "] is not of type [" + AbstractThymeleafView.class.getName() + "]");
        }
        this.viewClass = viewClass;
    }


    /**
     * <p>
     *   Return the view class to be used to create views.
     * </p>
     *
     * @return the view class.
     */
    protected Class<? extends AbstractThymeleafView> getViewClass() {
        return this.viewClass;
    }


    /**
     * <p>
     *   Returns the Thymeleaf template engine instance to be used for the
     *   execution of templates.
     * </p>
     *
     * @return the template engine being used for processing templates.
     */
    public ISpringTemplateEngine getTemplateEngine() {
        return this.templateEngine;
    }


    /**
     * <p>
     *   Sets the Template Engine instance to be used for processing
     *   templates.
     * </p>
     *
     * @param templateEngine the template engine to be used
     */
    public void setTemplateEngine(final ISpringTemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }



    /**
     * <p>
     *   Return the static variables, which will be available at the context
     *   every time a view resolved by this ViewResolver is processed.
     * </p>
     * <p>
     *   These static variables are added to the context by the view resolver
     *   before every view is processed, so that they can be referenced from
     *   the context like any other context variables, for example:
     *   {@code ${myStaticVar}}.
     * </p>
     *
     * @return the map of static variables to be set into views' execution.
     */
    public Map<String,Object> getStaticVariables() {
        return Collections.unmodifiableMap(this.staticVariables);
    }


    /**
     * <p>
     *   Add a new static variable.
     * </p>
     * <p>
     *   These static variables are added to the context by the view resolver
     *   before every view is processed, so that they can be referenced from
     *   the context like any other context variables, for example:
     *   {@code ${myStaticVar}}.
     * </p>
     *
     * @param name the name of the static variable
     * @param value the value of the static variable
     */
    public void addStaticVariable(final String name, final Object value) {
        this.staticVariables.put(name, value);
    }


    /**
     * <p>
     *   Sets a set of static variables, which will be available at the context
     *   every time a view resolved by this ViewResolver is processed.
     * </p>
     * <p>
     *   This method <b>does not overwrite</b> the existing static variables, it
     *   simply adds the ones specify to any variables already registered.
     * </p>
     * <p>
     *   These static variables are added to the context by the view resolver
     *   before every view is processed, so that they can be referenced from
     *   the context like any other context variables, for example:
     *   {@code ${myStaticVar}}.
     * </p>
     *
     *
     * @param variables the set of variables to be added.
     */
    public void setStaticVariables(final Map<String, ?> variables) {
        if (variables != null) {
            for (final Map.Entry<String, ?> entry : variables.entrySet()) {
                addStaticVariable(entry.getKey(), entry.getValue());
            }
        }
    }



    /**
     * <p>
     *   Specify the order in which this view resolver will be queried.
     * </p>
     * <p>
     *   Spring Web applications can have several view resolvers configured,
     *   and this {@code order} property established the order in which
     *   they will be queried for view resolution.
     * </p>
     *
     * @param order the order in which this view resolver will be asked to resolve
     *        the view.
     */
    public void setOrder(final int order) {
        this.order = order;
    }


    /**
     * <p>
     *   Returns the order in which this view resolver will be queried.
     * </p>
     * <p>
     *   Spring Web applications can have several view resolvers configured,
     *   and this {@code order} property established the order in which
     *   they will be queried for view resolution.
     * </p>
     *
     * @return the order
     */
    public int getOrder() {
        return this.order;
    }



    /**
     * <p>
     *   Sets the content type to be used when rendering views.
     * </p>
     * <p>
     *   This content type acts as a <i>default</i>, so that every view
     *   resolved by this resolver will use this content type unless there
     *   is a bean defined for such view that specifies a different content type.
     * </p>
     * <p>
     *   Therefore, individual views are allowed to specify their own content type
     *   regardless of the <i>application-wide</i> setting established here.
     * </p>
     * <p>
     *   If a content type is not specified (either here or at a specific view definition),
     *   {@link AbstractThymeleafView#DEFAULT_CONTENT_TYPE} will be used.
     * </p>
     *
     * @param contentType the content type to be used.
     */
    public void setContentType(final String contentType) {
        this.contentType = contentType;
    }



    /**
     * <p>
     *   Returns the content type that will be set into views resolved by this
     *   view resolver.
     * </p>
     * <p>
     *   This content type acts as a <i>default</i>, so that every view
     *   resolved by this resolver will use this content type unless there
     *   is a bean defined for such view that specifies a different content type.
     * </p>
     * <p>
     *   Therefore, individual views are allowed to specify their own content type
     *   regardless of the <i>application-wide</i> setting established here.
     * </p>
     * <p>
     *   If a content type is not specified (either at the view resolver or at a specific
     *   view definition), {@link AbstractThymeleafView#DEFAULT_CONTENT_TYPE} will be used.
     * </p>
     *
     * @return the content type currently configured
     */
    public String getContentType() {
        return this.contentType;
    }



    /**
     * <p>
     *   Returns whether the configured content type should be forced instead of attempting
     *   a <em>smart</em> content type application based on template name.
     * </p>
     * <p>
     *   When forced, the configured content type ({@link #setForceContentType(boolean)})  will
     *   be applied even if the template name ends in a known suffix:
     *   {@code .html}, {@code .htm}, {@code .xhtml},
     *   {@code .xml}, {@code .js}, {@code .json},
     *   {@code .css}, {@code .rss}, {@code .atom}, {@code .txt}.
     * </p>
     * <p>Default value is <b>{@code false}</b></p>.
     *
     * @return whether the content type will be forced or not.
     * @since 3.0.6
     */
    public boolean getForceContentType() {
        return this.forceContentType;
    }


    /**
     * <p>
     *   Sets whether the configured content type should be forced instead of attempting
     *   a <em>smart</em> content type application based on template name.
     * </p>
     * <p>
     *   When forced, the configured content type ({@link #setForceContentType(boolean)})  will
     *   be applied even if the template name ends in a known suffix:
     *   {@code .html}, {@code .htm}, {@code .xhtml},
     *   {@code .xml}, {@code .js}, {@code .json},
     *   {@code .css}, {@code .rss}, {@code .atom}, {@code .txt}.
     * </p>
     * <p>Default value is <b>{@code false}</b></p>.
     *
     * @param forceContentType whether the configured template mode should be forced or not.
     * @since 3.0.6
     */
    public void setForceContentType(final boolean forceContentType) {
        this.forceContentType = forceContentType;
    }




    /**
     * <p>
     *   Specifies the character encoding to be set into the response when
     *   the view is rendered.
     * </p>
     * <p>
     *   Many times, character encoding is specified as a part of the <i>content
     *   type</i>, using the {@link #setContentType(String)} or
     *   {@link AbstractThymeleafView#setContentType(String)}, but this is not mandatory,
     *   and it could be that only the MIME type is specified that way, thus allowing
     *   to set the character encoding using this method.
     * </p>
     * <p>
     *   As with {@link #setContentType(String)}, the value specified here acts as a
     *   default in case no character encoding has been specified at the view itself.
     *   If a view bean exists with the name of the view to be processed, and this
     *   view has been set a value for its {@link AbstractThymeleafView#setCharacterEncoding(String)}
     *   method, the value specified at the view resolver has no effect.
     * </p>
     *
     * @param characterEncoding the character encoding to be used (e.g. {@code UTF-8},
     *        {@code ISO-8859-1}, etc.)
     */
    public void setCharacterEncoding(final String characterEncoding) {
        this.characterEncoding = characterEncoding;
    }


    /**
     * <p>
     *   Returns the character encoding set to be used for all views resolved by
     *   this view resolver.
     * </p>
     * <p>
     *   Many times, character encoding is specified as a part of the <i>content
     *   type</i>, using the {@link #setContentType(String)} or
     *   {@link AbstractThymeleafView#setContentType(String)}, but this is not mandatory,
     *   and it could be that only the MIME type is specified that way, thus allowing
     *   to set the character encoding using the {@link #setCharacterEncoding(String)}
     *   counterpart of this getter method.
     * </p>
     * <p>
     *   As with {@link #setContentType(String)}, the value specified here acts as a
     *   default in case no character encoding has been specified at the view itself.
     *   If a view bean exists with the name of the view to be processed, and this
     *   view has been set a value for its {@link AbstractThymeleafView#setCharacterEncoding(String)}
     *   method, the value specified at the view resolver has no effect.
     * </p>
     *
     * @return the character encoding to be set at a view-resolver-wide level.
     */
    public String getCharacterEncoding() {
        return this.characterEncoding;
    }



    /**
     * <p>
     *   Set whether to interpret a given redirect URL that starts with a slash ("/")
     *   as relative to the current ServletContext, i.e. as relative to the web application root.
     * </p>
     * <p>
     *   Default is <b>{@code true}</b>: A redirect URL that starts with a slash will be interpreted
     *   as relative to the web application root, i.e. the context path will be prepended to the URL.
     * </p>
     * <p>
     *   Redirect URLs can be specified via the {@code "redirect:"} prefix. e.g.:
     *   {@code "redirect:myAction.do"}.
     * </p>
     *
     * @param redirectContextRelative whether redirect URLs should be considered context-relative or not.
     * @see RedirectView#setContextRelative(boolean)
     */
    public void setRedirectContextRelative(final boolean redirectContextRelative) {
        this.redirectContextRelative = redirectContextRelative;
    }


    /**
     * <p>
     *   Return whether to interpret a given redirect URL that starts with a slash ("/")
     *   as relative to the current ServletContext, i.e. as relative to the web application root.
     * </p>
     * <p>
     *   Default is <b>{@code true}</b>.
     * </p>
     *
     * @return true if redirect URLs will be considered relative to context, false if not.
     * @see RedirectView#setContextRelative(boolean)
     */
    public boolean isRedirectContextRelative() {
        return this.redirectContextRelative;
    }



    /**
     * <p>
     *   Set whether redirects should stay compatible with HTTP 1.0 clients.
     * </p>
     * <p>
     *   In the default implementation (default is <b>{@code true}</b>), this will enforce HTTP status
     *   code 302 in any case, i.e. delegate to
     *   {@link jakarta.servlet.http.HttpServletResponse#sendRedirect(String)}. Turning this off
     *   will send HTTP status code 303, which is the correct code for HTTP 1.1 clients, but not understood
     *   by HTTP 1.0 clients.
     * </p>
     * <p>
     *   Many HTTP 1.1 clients treat 302 just like 303, not making any difference. However, some clients
     *   depend on 303 when redirecting after a POST request; turn this flag off in such a scenario.
     * </p>
     * <p>
     *   Redirect URLs can be specified via the {@code "redirect:"} prefix. e.g.:
     *   {@code "redirect:myAction.do"}
     * </p>
     *
     * @param redirectHttp10Compatible true if redirects should stay compatible with HTTP 1.0 clients,
     *        false if not.
     * @see RedirectView#setHttp10Compatible(boolean)
     */
    public void setRedirectHttp10Compatible(final boolean redirectHttp10Compatible) {
        this.redirectHttp10Compatible = redirectHttp10Compatible;
    }


    /**
     * <p>
     *   Return whether redirects should stay compatible with HTTP 1.0 clients.
     * </p>
     * <p>
     *   Default is <b>{@code true}</b>.
     * </p>
     *
     * @return whether redirect responses should stay compatible with HTTP 1.0 clients.
     * @see RedirectView#setHttp10Compatible(boolean)
     */
    public boolean isRedirectHttp10Compatible() {
        return this.redirectHttp10Compatible;
    }



    /**
     * <p>
     *   Set whether this view resolver should always process forwards and redirects independently of the value of
     *   the {@code viewNames} property.
     * </p>
     * <p>
     *   When this flag is set to {@code true} (default value), any view name that starts with the
     *   {@code redirect:} or {@code forward:} prefixes will be resolved by this ViewResolver even if the view names
     *   would not match what is established at the {@code viewNames} property.
     * </p>
     * <p>
     *   Note that the behaviour of <em>resolving</em> view names with these prefixes is exactly the same with this
     *   flag set to {@code true} or {@code false} (perform an HTTP redirect or forward to an internal JSP resource).
     *   The only difference is whether the prefixes have to be explicitly specified at {@code viewNames} or not.
     * </p>
     * <p>
     *   Default value is {@code true}.
     * </p>
     *
     * @param alwaysProcessRedirectAndForward true if redirects and forwards are always processed, false if this will
     *                                     depend on what is established at the viewNames property.
     */
    public void setAlwaysProcessRedirectAndForward(final boolean alwaysProcessRedirectAndForward) {
        this.alwaysProcessRedirectAndForward = alwaysProcessRedirectAndForward;
    }


    /**
     * <p>
     *   Return whether this view resolver should always process forwards and redirects independently of the value of
     *   the {@code viewNames} property.
     * </p>
     * <p>
     *   When this flag is set to {@code true} (default value), any view name that starts with the
     *   {@code redirect:} or {@code forward:} prefixes will be resolved by this ViewResolver even if the view names
     *   would not match what is established at the {@code viewNames} property.
     * </p>
     * <p>
     *   Note that the behaviour of <em>resolving</em> view names with these prefixes is exactly the same with this
     *   flag set to {@code true} or {@code false} (perform an HTTP redirect or forward to an internal JSP resource).
     *   The only difference is whether the prefixes have to be explicitly specified at {@code viewNames} or not.
     * </p>
     * <p>
     *   Default value is {@code true}.
     * </p>
     *
     * @return whether redirects and forwards will be always processed by this view resolver or else only when they are
     *         matched by the {@code viewNames} property.
     *
     */
    public boolean getAlwaysProcessRedirectAndForward() {
        return this.alwaysProcessRedirectAndForward;
    }




    /**
     * <p>
     *   Returns whether Thymeleaf should start producing output &ndash;and sending it to the web server's output
     *   buffers&ndash; as soon as possible, outputting partial results while processing as they become available so
     *   that they can potentially be sent to the client (browser) before processing of the whole template has
     *   completely finished.
     * </p>
     * <p>
     *   If set to {@code false}, no fragments of template result will be sent to the web server's
     *   output buffers until Thymeleaf completely finishes processing the template and generating
     *   the corresponding output. Only once finished will output start to be written to the web server's
     *   output buffers, and therefore sent to the clients.
     * </p>
     * <p>
     *   Note that setting this to {@code false} is <strong>not recommended for most
     *   scenarios</strong>, as it can (very) significantly increase the amount of memory used per
     *   template execution. Only modify this setting if you know what you are doing. A typical
     *   scenario in which setting this to {@code false} could be of use is when an application is
     *   suffering from UI rendering issues (flickering) at the browser due to incremental
     *   rendering of very large templates.
     * </p>
     * <p>
     *   Default value is {@code true}.
     * </p>
     *
     * @return whether to start producing output as soon as possible while processing or not (default: {@code true}).
     * @since 3.0.10
     */
    public boolean getProducePartialOutputWhileProcessing() {
        return this.producePartialOutputWhileProcessing;
    }


    /**
     * <p>
     *   Sets whether Thymeleaf should start producing output &ndash;and sending it to the web server's output
     *   buffers&ndash; as soon as possible, outputting partial results while processing as they become available so
     *   that they can potentially be sent to the client (browser) before processing of the whole template has
     *   completely finished.
     * </p>
     * <p>
     *   If set to {@code false}, no fragments of template result will be sent to the web server's
     *   output buffers until Thymeleaf completely finishes processing the template and generating
     *   the corresponding output. Only once finished will output start to be written to the web server's
     *   output buffers, and therefore sent to the clients.
     * </p>
     * <p>
     *   Note that setting this to {@code false} is <strong>not recommended for most
     *   scenarios</strong>, as it can (very) significantly increase the amount of memory used per
     *   template execution. Only modify this setting if you know what you are doing. A typical
     *   scenario in which setting this to {@code false} could be of use is when an application is
     *   suffering from UI rendering issues (flickering) at the browser due to incremental
     *   rendering of very large templates.
     * </p>
     * <p>
     *   Default value is {@code true}.
     * </p>
     *
     * @param producePartialOutputWhileProcessing whether to start producing output as soon as possible while
     *                                            processing or not (default: {@code true}).
     * @since 3.0.10
     */
    public void setProducePartialOutputWhileProcessing(final boolean producePartialOutputWhileProcessing) {
        this.producePartialOutputWhileProcessing = producePartialOutputWhileProcessing;
    }




    /**
     * <p>
     *   Specify a set of name patterns that will applied to determine whether a view name
     *   returned by a controller will be resolved by this resolver or not.
     * </p>
     * <p>
     *   In applications configuring several view resolvers &ndash;for example, one for Thymeleaf
     *   and another one for JSP+JSTL legacy pages&ndash;, this property establishes when
     *   a view will be considered to be resolved by this view resolver and when Spring should
     *   simply ask the next resolver in the chain &ndash;according to its {@code order}&ndash;
     *   instead.
     * </p>
     * <p>
     *   The specified view name patterns can be complete view names, but can also use
     *   the {@code *} wildcard: "{@code index.*}", "{@code user_*}", "{@code admin/*}", etc.
     * </p>
     * <p>
     *   Also note that these view name patterns are checked <i>before</i> applying any prefixes
     *   or suffixes to the view name, so they should not include these. Usually therefore, you
     *   would specify {@code orders/*} instead of {@code /WEB-INF/templates/orders/*.html}.
     * </p>
     *
     * @param viewNames the view names (actually view name patterns)
     * @see PatternMatchUtils#simpleMatch(String[], String)
     */
    public void setViewNames(final String[] viewNames) {
        this.viewNames = viewNames;
    }


    /**
     * <p>
     *   Return the set of name patterns that will applied to determine whether a view name
     *   returned by a controller will be resolved by this resolver or not.
     * </p>
     * <p>
     *   In applications configuring several view resolvers &ndash;for example, one for Thymeleaf
     *   and another one for JSP+JSTL legacy pages&ndash;, this property establishes when
     *   a view will be considered to be resolved by this view resolver and when Spring should
     *   simply ask the next resolver in the chain &ndash;according to its {@code order}&ndash;
     *   instead.
     * </p>
     * <p>
     *   The specified view name patterns can be complete view names, but can also use
     *   the {@code *} wildcard: "{@code index.*}", "{@code user_*}", "{@code admin/*}", etc.
     * </p>
     * <p>
     *   Also note that these view name patterns are checked <i>before</i> applying any prefixes
     *   or suffixes to the view name, so they should not include these. Usually therefore, you
     *   would specify {@code orders/*} instead of {@code /WEB-INF/templates/orders/*.html}.
     * </p>
     *
     * @return the view name patterns
     * @see PatternMatchUtils#simpleMatch(String[], String)
     */
    public String[] getViewNames() {
        return this.viewNames;
    }




    /**
     * <p>
     *   Specify names of views &ndash;patterns, in fact&ndash; that cannot
     *   be handled by this view resolver.
     * </p>
     * <p>
     *   These patterns can be specified in the same format as those in
     *   {@link #setViewNames(String[])}, but work as an <i>exclusion list</i>.
     * </p>
     *
     * @param excludedViewNames the view names to be excluded (actually view name patterns)
     * @see ThymeleafViewResolver#setViewNames(String[])
     * @see PatternMatchUtils#simpleMatch(String[], String)
     */
    public void setExcludedViewNames(final String[] excludedViewNames) {
        this.excludedViewNames = excludedViewNames;
    }


    /**
     * <p>
     *   Returns the names of views &ndash;patterns, in fact&ndash; that cannot
     *   be handled by this view resolver.
     * </p>
     * <p>
     *   These patterns can be specified in the same format as those in
     *   {@link #setViewNames(String[])}, but work as an <i>exclusion list</i>.
     * </p>
     *
     * @return the excluded view name patterns
     * @see ThymeleafViewResolver#getViewNames()
     * @see PatternMatchUtils#simpleMatch(String[], String)
     */
    public String[] getExcludedViewNames() {
        return this.excludedViewNames;
    }




    protected boolean canHandle(final String viewName, @SuppressWarnings("unused") final Locale locale) {
        final String[] viewNamesToBeProcessed = getViewNames();
        final String[] viewNamesNotToBeProcessed = getExcludedViewNames();
        return ((viewNamesToBeProcessed == null || PatternMatchUtils.simpleMatch(viewNamesToBeProcessed, viewName)) &&
                (viewNamesNotToBeProcessed == null || !PatternMatchUtils.simpleMatch(viewNamesNotToBeProcessed, viewName)));
    }




    @Override
    protected View createView(final String viewName, final Locale locale) throws Exception {
        // First possible call to check "viewNames": before processing redirects and forwards
        if (!this.alwaysProcessRedirectAndForward && !canHandle(viewName, locale)) {
            vrlogger.trace("[THYMELEAF] View \"{}\" cannot be handled by ThymeleafViewResolver. Passing on to the next resolver in the chain.", viewName);
            return null;
        }
        // Process redirects (HTTP redirects)
        if (viewName.startsWith(REDIRECT_URL_PREFIX)) {
            vrlogger.trace("[THYMELEAF] View \"{}\" is a redirect, and will not be handled directly by ThymeleafViewResolver.", viewName);
            final String redirectUrl = viewName.substring(REDIRECT_URL_PREFIX.length(), viewName.length());
            final RedirectView view = new RedirectView(redirectUrl, isRedirectContextRelative(), isRedirectHttp10Compatible());
            return (View) getApplicationContext().getAutowireCapableBeanFactory().initializeBean(view, REDIRECT_URL_PREFIX);
        }
        // Process forwards (to JSP resources)
        if (viewName.startsWith(FORWARD_URL_PREFIX)) {
            // The "forward:" prefix will actually create a Servlet/JSP view, and that's precisely its aim per the Spring
            // documentation. See http://docs.spring.io/spring-framework/docs/4.2.4.RELEASE/spring-framework-reference/html/mvc.html#mvc-redirecting-forward-prefix
            vrlogger.trace("[THYMELEAF] View \"{}\" is a forward, and will not be handled directly by ThymeleafViewResolver.", viewName);
            final String forwardUrl = viewName.substring(FORWARD_URL_PREFIX.length(), viewName.length());
            return new InternalResourceView(forwardUrl);
        }
        // Second possible call to check "viewNames": after processing redirects and forwards
        if (this.alwaysProcessRedirectAndForward && !canHandle(viewName, locale)) {
            vrlogger.trace("[THYMELEAF] View \"{}\" cannot be handled by ThymeleafViewResolver. Passing on to the next resolver in the chain.", viewName);
            return null;
        }
        vrlogger.trace("[THYMELEAF] View {} will be handled by ThymeleafViewResolver and a " +
                        "{} instance will be created for it", viewName, getViewClass().getSimpleName());
        return loadView(viewName, locale);
    }




    @Override
    protected View loadView(final String viewName, final Locale locale) throws Exception {

        final AutowireCapableBeanFactory beanFactory = getApplicationContext().getAutowireCapableBeanFactory();

        final boolean viewBeanExists = beanFactory.containsBean(viewName);
        final Class<?> viewBeanType = viewBeanExists? beanFactory.getType(viewName) : null;

        final AbstractThymeleafView view;
        if (viewBeanExists && viewBeanType != null && AbstractThymeleafView.class.isAssignableFrom(viewBeanType)) {
            // AppCtx has a bean with name == viewName, and it is a View bean. So let's use it as a prototype!
            //
            // This can mean two things: if the bean has been defined with scope "prototype", we will just use it.
            // If it hasn't we will create a new instance of the view class and use its properties in order to
            // configure this view instance (so that we don't end up using the same bean from several request threads).
            //
            // Note that, if Java-based configuration is used, using @Scope("prototype") would be the only viable
            // possibility here.

            final BeanDefinition viewBeanDefinition =
                    (beanFactory instanceof ConfigurableListableBeanFactory ?
                            ((ConfigurableListableBeanFactory)beanFactory).getBeanDefinition(viewName) :
                            null);

            if (viewBeanDefinition == null || !viewBeanDefinition.isPrototype()) {
                // No scope="prototype", so we will just apply its properties. This should only happen with XML config.
                final AbstractThymeleafView viewInstance = BeanUtils.instantiateClass(getViewClass());
                view = (AbstractThymeleafView) beanFactory.configureBean(viewInstance, viewName);
            } else {
                // This is a prototype bean. Use it as such.
                view = (AbstractThymeleafView) beanFactory.getBean(viewName);
            }

        } else {

            final AbstractThymeleafView viewInstance = BeanUtils.instantiateClass(getViewClass());

            if (viewBeanExists && viewBeanType == null) {
                // AppCtx has a bean with name == viewName, but it is an abstract bean. We still can use it as a prototype.

                // The AUTOWIRE_NO mode applies autowiring only through annotations
                beanFactory.autowireBeanProperties(viewInstance, AutowireCapableBeanFactory.AUTOWIRE_NO, false);
                // A bean with this name exists, so we apply its properties
                beanFactory.applyBeanPropertyValues(viewInstance, viewName);
                // Finally, we let Spring do the remaining initializations (incl. proxifying if needed)
                view = (AbstractThymeleafView) beanFactory.initializeBean(viewInstance, viewName);

            } else {
                // Either AppCtx has no bean with name == viewName, or it is of an incompatible class. No prototyping done.

                // The AUTOWIRE_NO mode applies autowiring only through annotations
                beanFactory.autowireBeanProperties(viewInstance, AutowireCapableBeanFactory.AUTOWIRE_NO, false);
                // Finally, we let Spring do the remaining initializations (incl. proxifying if needed)
                view = (AbstractThymeleafView) beanFactory.initializeBean(viewInstance, viewName);

            }

        }

        view.setTemplateEngine(getTemplateEngine());
        view.setStaticVariables(getStaticVariables());


        // We give view beans the opportunity to specify the template name to be used
        if (view.getTemplateName() == null) {
            view.setTemplateName(viewName);
        }

        if (!view.isForceContentTypeSet()) {
            view.setForceContentType(getForceContentType());
        }
        if (!view.isContentTypeSet() && getContentType() != null) {
            view.setContentType(getContentType());
        }
        if (view.getLocale() == null && locale != null) {
            view.setLocale(locale);
        }
        if (view.getCharacterEncoding() == null && getCharacterEncoding() != null) {
            view.setCharacterEncoding(getCharacterEncoding());
        }
        if (!view.isProducePartialOutputWhileProcessingSet()) {
            view.setProducePartialOutputWhileProcessing(getProducePartialOutputWhileProcessing());
        }

        return view;

    }


}

/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jdbi.v3.core.async;

import java.util.concurrent.CompletionStage;

import org.jdbi.v3.core.HandleCallback;
import org.jdbi.v3.core.HandleConsumer;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.core.extension.ExtensionCallback;
import org.jdbi.v3.core.extension.ExtensionConsumer;
import org.jdbi.v3.core.internal.exceptions.CheckedConsumer;
import org.jdbi.v3.core.internal.exceptions.CheckedFunction;
import org.jdbi.v3.core.transaction.TransactionIsolationLevel;
import org.jdbi.v3.meta.Beta;

@Beta
public abstract class AbstractJdbiExecutor implements JdbiExecutor {

    /**
     * Single method through which all other with* methods converge. Since useExecute also calls this, any implementation of AbstractJdbiExecutor only needs to
     * implement this method
     *
     * @param callback the callback that takes a Jdbi instance and returns a value
     * @param <T>      type returned by the callback
     * @return a completion stage that will complete when the handler returns a value or throws an exception
     */
    protected abstract <T> CompletionStage<T> withExecute(CheckedFunction<Jdbi, T> callback);

    /**
     * Single method through which all other use* methods converge. This method calls {@link #withExecute(CheckedFunction)}
     *
     * @param callback the callback that takes a Jdbi instance
     * @return a completion stage that will complete when the handler returns or throws an exception
     */
    protected CompletionStage<Void> useExecute(CheckedConsumer<Jdbi> callback) {
        return withExecute(jdbi -> {
            callback.accept(jdbi);
            return null;
        });
    }

    @Override
    public <R, X extends Exception> CompletionStage<R> withHandle(final HandleCallback<R, X> callback) {
        return withExecute(jdbi -> jdbi.withHandle(callback));
    }

    @Override
    public <R, X extends Exception> CompletionStage<R> inTransaction(final HandleCallback<R, X> callback) {
        return withExecute(jdbi -> jdbi.inTransaction(callback));
    }

    @Override
    public <R, X extends Exception> CompletionStage<R> inTransaction(final TransactionIsolationLevel level, final HandleCallback<R, X> callback) {
        return withExecute(jdbi -> jdbi.inTransaction(level, callback));
    }

    @Override
    public <X extends Exception> CompletionStage<Void> useHandle(final HandleConsumer<X> consumer) {
        return useExecute(jdbi -> jdbi.useHandle(consumer));
    }

    @Override
    public <X extends Exception> CompletionStage<Void> useTransaction(final HandleConsumer<X> callback) {
        return useExecute(jdbi -> jdbi.useTransaction(callback));
    }

    @Override
    public <X extends Exception> CompletionStage<Void> useTransaction(final TransactionIsolationLevel level, final HandleConsumer<X> callback) {
        return useExecute(jdbi -> jdbi.useTransaction(level, callback));
    }

    @Override
    public <R, E, X extends Exception> CompletionStage<R> withExtension(final Class<E> extensionType, final ExtensionCallback<R, E, X> callback) {
        return withExecute(jdbi -> jdbi.withExtension(extensionType, callback));
    }

    @Override
    public <E, X extends Exception> CompletionStage<Void> useExtension(final Class<E> extensionType, final ExtensionConsumer<E, X> callback) {
        return useExecute(jdbi -> jdbi.useExtension(extensionType, callback));
    }
}

  static class MemoizingSupplier<T extends @Nullable Object> implements Supplier<T>, Serializable {
    private transient Object lock = new Object();

    final Supplier<T> delegate;
    transient volatile boolean initialized;
    // "value" does not need to be volatile; visibility piggy-backs
    // on volatile read of "initialized".
    transient @Nullable T value;

    MemoizingSupplier(Supplier<T> delegate) {
      this.delegate = checkNotNull(delegate);
    }

    @Override
    @ParametricNullness
    // We set the field only once (during construction or deserialization).
    @SuppressWarnings("SynchronizeOnNonFinalField")
    public T get() {
      // A 2-field variant of Double Checked Locking.
      if (!initialized) {
        synchronized (lock) {
          if (!initialized) {
            T t = delegate.get();
            value = t;
            initialized = true;
            return t;
          }
        }
      }
      // This is safe because we checked `initialized`.
      return uncheckedCastNullableTToT(value);
    }

    @Override
    public String toString() {
      return "Suppliers.memoize("
          + (initialized ? "<supplier that returned " + value + ">" : delegate)
          + ")";
    }

    @GwtIncompatible // serialization
    @J2ktIncompatible // serialization
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
      in.defaultReadObject();
      lock = new Object();
    }

    @GwtIncompatible @J2ktIncompatible private static final long serialVersionUID = 0;
  } 




