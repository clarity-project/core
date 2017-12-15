<?php

/*
 * This file is part of the API Platform project.
 *
 * (c) Kévin Dunglas <dunglas@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace ApiPlatform\Core\Metadata\Property\Factory;

use ApiPlatform\Core\Exception\ResourceClassNotFoundException;
use ApiPlatform\Core\Metadata\Property\PropertyMetadata;
use ApiPlatform\Core\Metadata\Resource\Factory\ResourceMetadataFactoryInterface;
use ApiPlatform\Core\Security\ExpressionLanguage;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface;
use Symfony\Component\Serializer\Mapping\Factory\ClassMetadataFactoryInterface as SerializerClassMetadataFactoryInterface;

/**
 * Populates read/write and link status using serialization groups.
 *
 * @author Kévin Dunglas <dunglas@gmail.com>
 * @author Teoh Han Hui <teohhanhui@gmail.com>
 */
final class SerializerPropertyMetadataFactory implements PropertyMetadataFactoryInterface
{
    private $resourceMetadataFactory;
    private $serializerClassMetadataFactory;
    private $decorated;
    private $expressionLanguage;
    private $authenticationTrustResolver;
    private $roleHierarchy;
    private $tokenStorage;
    private $authorizationChecker;

    public function __construct(
        ResourceMetadataFactoryInterface $resourceMetadataFactory,
        SerializerClassMetadataFactoryInterface $serializerClassMetadataFactory,
        PropertyMetadataFactoryInterface $decorated,
        ExpressionLanguage $expressionLanguage = null,
        AuthenticationTrustResolverInterface $authenticationTrustResolver = null,
        RoleHierarchyInterface $roleHierarchy = null,
        TokenStorageInterface $tokenStorage = null,
        AuthorizationCheckerInterface $authorizationChecker = null
    )
    {
        $this->resourceMetadataFactory = $resourceMetadataFactory;
        $this->serializerClassMetadataFactory = $serializerClassMetadataFactory;
        $this->decorated = $decorated;
        $this->expressionLanguage = $expressionLanguage;
        $this->authenticationTrustResolver = $authenticationTrustResolver;
        $this->roleHierarchy = $roleHierarchy;
        $this->tokenStorage = $tokenStorage;
        $this->authorizationChecker = $authorizationChecker;
    }


    /* -==================  @todo: refactoring to have as a service */

    /**
     * @param $resourceClass
     * @return array
     */
    protected function getVariables($resourceClass)
    {
        if (null === $this->tokenStorage || null === $this->authenticationTrustResolver) {
            throw new \LogicException(sprintf('The "symfony/security" library must be installed to use the "access_control" attribute on class "%s".', $resourceClass));
        }
        if (null === $this->tokenStorage->getToken()) {
            throw new \LogicException(sprintf('The resource must be behind a firewall to use the "access_control" attribute on class "%s".', $resourceClass));
        }
        if (null === $this->expressionLanguage) {
            throw new \LogicException(sprintf('The "symfony/expression-language" library must be installed to use the "access_control" attribute on class "%s".', $resourceClass));
        }

        $token = $this->tokenStorage->getToken();
        $roles = $this->roleHierarchy ? $this->roleHierarchy->getReachableRoles($token->getRoles()) : $token->getRoles();

        return [
            'token' => $token,
            'user' => $token->getUser(),
            'roles' => array_map(function (Role $role) {
                return $role->getRole();
            }, $roles),
            'trust_resolver' => $this->authenticationTrustResolver,
            // needed for the is_granted expression function
            'auth_checker' => $this->authorizationChecker,
        ];
    }

    /**
     * @param array $groups
     * @return array
     */
    protected function extractGroups(array $groups, $resourceClass)
    {
        $serializerGroups = [];
        foreach ($groups as $group => $groupConfiguration) {
            if (is_array($groupConfiguration)) {
                if (php_sapi_name() == 'cli') {
                    $serializerGroups[] = $group;
                } else if (array_key_exists('access_control', $groupConfiguration) &&
                    $this->expressionLanguage->evaluate($groupConfiguration['access_control'], $this->getVariables($resourceClass))
                ) {
                    $serializerGroups[] = $group;
                }
            } else {
                $serializerGroups[] = $groupConfiguration; // this means, that group was passed as simple string without configs
            }
        }

        return $serializerGroups;
    }


    /* -================== END of @todo */


    /**
     * {@inheritdoc}
     */
    public function create(string $resourceClass, string $property, array $options = []): PropertyMetadata
    {
        $propertyMetadata = $this->decorated->create($resourceClass, $property, $options);

        // in case of a property inherited (in a child class), we need it's properties
        // to be mapped against serialization groups instead of the parent ones.
        if (null !== ($childResourceClass = $propertyMetadata->isChildInherited())) {
            $resourceClass = $childResourceClass;
        }

        list($normalizationGroups, $denormalizationGroups) = $this->getEffectiveSerializerGroups($options, $resourceClass);

        $normalizationGroups = $this->extractGroups($normalizationGroups, $resourceClass);
        $denormalizationGroups = $this->extractGroups($denormalizationGroups, $resourceClass);

        $propertyMetadata = $this->transformReadWrite($propertyMetadata, $resourceClass, $property, $normalizationGroups, $denormalizationGroups);
        $propertyMetadata = $this->transformLinkStatus($propertyMetadata, $normalizationGroups, $denormalizationGroups);

        return $propertyMetadata;
    }

    /**
     * Sets readable/writable based on matching normalization/denormalization groups.
     *
     * A false value is never reset as it could be unreadable/unwritable for other reasons.
     * If normalization/denormalization groups are not specified, the property is implicitly readable/writable.
     *
     * @param PropertyMetadata $propertyMetadata
     * @param string           $resourceClass
     * @param string           $propertyName
     * @param string[]|null    $normalizationGroups
     * @param string[]|null    $denormalizationGroups
     *
     * @return PropertyMetadata
     */
    private function transformReadWrite(PropertyMetadata $propertyMetadata, string $resourceClass, string $propertyName, array $normalizationGroups = null, array $denormalizationGroups = null): PropertyMetadata
    {
        $groups = $this->getPropertySerializerGroups($resourceClass, $propertyName);

        if (false !== $propertyMetadata->isReadable()) {
            $propertyMetadata = $propertyMetadata->withReadable(null === $normalizationGroups || !empty(array_intersect($normalizationGroups, $groups)));
        }

        if (false !== $propertyMetadata->isWritable()) {
            $propertyMetadata = $propertyMetadata->withWritable(null === $denormalizationGroups || !empty(array_intersect($denormalizationGroups, $groups)));
        }

        return $propertyMetadata;
    }

    /**
     * Sets readableLink/writableLink based on matching normalization/denormalization groups.
     *
     * If normalization/denormalization groups are not specified,
     * set link status to false since embedding of resource must be explicitly enabled
     *
     * @param PropertyMetadata $propertyMetadata
     * @param string[]|null    $normalizationGroups
     * @param string[]|null    $denormalizationGroups
     *
     * @return PropertyMetadata
     */
    private function transformLinkStatus(PropertyMetadata $propertyMetadata, array $normalizationGroups = null, array $denormalizationGroups = null): PropertyMetadata
    {
        $propertyMetadata = $propertyMetadata->withReadableLink(true);
        $propertyMetadata = $propertyMetadata->withWritableLink(true);

        // No need to check link status if property is not readable and not writable
        if (false === $propertyMetadata->isReadable() && false === $propertyMetadata->isWritable()) {
            return $propertyMetadata;
        }

        $type = $propertyMetadata->getType();
        if (null === $type) {
            return $propertyMetadata;
        }

        $relatedClass = $type->isCollection() && ($collectionValueType = $type->getCollectionValueType()) ? $collectionValueType->getClassName() : $type->getClassName();

        if (null === $relatedClass) {
            return $propertyMetadata;
        }

        // No need to check link status if related class is not a resource
        try {
            $this->resourceMetadataFactory->create($relatedClass);
        } catch (ResourceClassNotFoundException $e) {
            return $propertyMetadata;
        }

        $relatedGroups = $this->getResourceSerializerGroups($relatedClass);

        $propertyMetadata = $propertyMetadata->withReadableLink(null !== $normalizationGroups && !empty(array_intersect($normalizationGroups, $relatedGroups)));
        $propertyMetadata = $propertyMetadata->withWritableLink(null !== $denormalizationGroups && !empty(array_intersect($denormalizationGroups, $relatedGroups)));

        return $propertyMetadata;
    }

    /**
     * Gets the effective serializer groups used in normalization/denormalization.
     *
     * Groups are extracted in the following order:
     *
     * - From the "serializer_groups" key of the $options array.
     * - From metadata of the given operation ("collection_operation_name" and "item_operation_name" keys).
     * - From metadata of the current resource.
     *
     * @param array  $options
     * @param string $resourceClass
     *
     * @return (string[]|null)[]
     */
    private function getEffectiveSerializerGroups(array $options, string $resourceClass): array
    {
        if (isset($options['serializer_groups'])) {
            return [$options['serializer_groups'], $options['serializer_groups']];
        }

        $resourceMetadata = $this->resourceMetadataFactory->create($resourceClass);
        if (isset($options['collection_operation_name'])) {
            $normalizationContext = $resourceMetadata->getCollectionOperationAttribute($options['collection_operation_name'], 'normalization_context', null, true);
            $denormalizationContext = $resourceMetadata->getCollectionOperationAttribute($options['collection_operation_name'], 'denormalization_context', null, true);
        } elseif (isset($options['item_operation_name'])) {
            $normalizationContext = $resourceMetadata->getItemOperationAttribute($options['item_operation_name'], 'normalization_context', null, true);
            $denormalizationContext = $resourceMetadata->getItemOperationAttribute($options['item_operation_name'], 'denormalization_context', null, true);
        } else {
            $normalizationContext = $resourceMetadata->getAttribute('normalization_context');
            $denormalizationContext = $resourceMetadata->getAttribute('denormalization_context');
        }

        return [$normalizationContext['groups'] ?? null, $denormalizationContext['groups'] ?? null];
    }

    /**
     * Gets the serializer groups defined on a property.
     *
     * @param string $resourceClass
     * @param string $property
     *
     * @return string[]
     */
    private function getPropertySerializerGroups(string $resourceClass, string $property): array
    {
        $serializerClassMetadata = $this->serializerClassMetadataFactory->getMetadataFor($resourceClass);

        foreach ($serializerClassMetadata->getAttributesMetadata() as $serializerAttributeMetadata) {
            if ($property === $serializerAttributeMetadata->getName()) {
                return $serializerAttributeMetadata->getGroups();
            }
        }

        return [];
    }

    /**
     * Gets the serializer groups defined in a resource.
     *
     * @param string $resourceClass
     *
     * @return string[]
     */
    private function getResourceSerializerGroups(string $resourceClass): array
    {
        $serializerClassMetadata = $this->serializerClassMetadataFactory->getMetadataFor($resourceClass);

        $groups = [];

        foreach ($serializerClassMetadata->getAttributesMetadata() as $serializerAttributeMetadata) {
            $groups = array_merge($groups, $serializerAttributeMetadata->getGroups());
        }

        return array_unique($groups);
    }
}
